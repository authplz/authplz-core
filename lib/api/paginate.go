/* AuthPlz Authentication and Authorization Microservice
 * Messages and types for pagination
 *
 * Copyright 2018 Ryan Kurte
 */

package api

type Paginate struct {
	Count  uint
	Offset uint
}
