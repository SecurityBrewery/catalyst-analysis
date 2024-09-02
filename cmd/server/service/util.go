package service

func mapSlice[T any, U any](s []T, f func(T) U) []U {
	r := make([]U, 0, len(s))

	for _, v := range s {
		r = append(r, f(v))
	}

	return r
}

func pointer[T any](t T) *T {
	return &t
}
