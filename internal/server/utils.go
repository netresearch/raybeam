package server

import "github.com/gofiber/fiber/v2"

func sendError(c *fiber.Ctx, statusCode int, reason string) error {
	if acceptsJson(c) {
		return c.Status(statusCode).JSON(map[string]interface{}{
			"success": false,
			"error":   reason,
		})
	}

	return c.Status(statusCode).SendString(reason)
}

func acceptsJson(c *fiber.Ctx) bool {
	return c.Get(fiber.HeaderAccept) == fiber.MIMEApplicationJSON
}
