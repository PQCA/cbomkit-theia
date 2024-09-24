// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"io"
	"net/http"

	"github.com/IBM/cbomkit-theia/provider/docker"
	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/IBM/cbomkit-theia/scanner"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	"go.uber.org/dig"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type imageGetRequest struct {
	Image   string   `json:"image" binding:"required"`
	Plugins []string `json:"plugins" example:"certificates"`
	Bom     *cdx.BOM `json:"bom"`
}

type errorResponse struct {
	Err string `json:"error"`
}

func Serve() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(cors.Default()) // Allow all origins
	err := r.SetTrustedProxies(nil)
	if err != nil {
		return
	}
	v1 := r.Group("/api/v1")
	{
		v1.POST("/image", imageGet)
	}
	err = r.Run(":8080") // listen and serve on 0.0.0.0:8080
	if err != nil {
		return
	}
}

func imageGet(c *gin.Context) {
	request := imageGetRequest{
		Plugins: scanner.GetAllPluginNames(),
		Bom:     scanner.NewBOMWithMetadata(),
	}
	if err := c.ShouldBindBodyWithJSON(&request); err != nil {
		returnError(c, err)
		return
	} else {
		image, err := docker.GetPrebuiltImage(request.Image)
		if err != nil {
			returnError(c, err)
			return
		}
		defer image.TearDown()

		container := dig.New()

		if err = container.Provide(func() filesystem.Filesystem {
			return docker.GetSquashedFilesystem(image)
		}); err != nil {
			returnError(c, err)
			return
		}

		if err = container.Provide(func() *cdx.BOM {
			return request.Bom
		}); err != nil {
			returnError(c, err)
			return
		}

		output := new(bytes.Buffer)

		if err = container.Provide(func() io.Writer {
			return output
		}); err != nil {
			returnError(c, err)
			return
		}

		if err = container.Provide(func() ([]plugins.PluginConstructor, error) {
			return scanner.GetPluginConstructorsFromNames(request.Plugins)
		}); err != nil {
			returnError(c, err)
			return
		}

		if err = container.Provide(func(input []plugins.PluginConstructor) ([]plugins.Plugin, error) {
			p := make([]plugins.Plugin, len(input))
			for i, con := range input {
				p[i], err = con()
				if err != nil {
					return p, err
				}
			}
			return p, nil
		}); err != nil {
			returnError(c, err)
			return
		}

		if err = container.Invoke(scanner.RunScan); err != nil {
			returnError(c, err)
			return
		}

		c.DataFromReader(http.StatusOK, int64(len(output.Bytes())), "application/vnd.cyclonedx+json; version=1.6", output, map[string]string{})
	}
}

func returnError(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, errorResponse{Err: err.Error()})
}
