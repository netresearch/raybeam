package server

import (
	"raybeam/internal/build"

	"github.com/gofiber/fiber/v2"
)

func (s *Server) handleHTTPGetInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"version": build.Version,
		"source":  build.Repository,
	})
}
