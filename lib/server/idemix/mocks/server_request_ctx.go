// Code generated by mockery v2.7.4. DO NOT EDIT.

package mocks

import (
	user "github.com/bestchains/fabric-ca/lib/server/user"
	mock "github.com/stretchr/testify/mock"
)

// ServerRequestCtx is an autogenerated mock type for the ServerRequestCtx type
type ServerRequestCtx struct {
	mock.Mock
}

// BasicAuthentication provides a mock function with given fields:
func (_m *ServerRequestCtx) BasicAuthentication() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCaller provides a mock function with given fields:
func (_m *ServerRequestCtx) GetCaller() (user.User, error) {
	ret := _m.Called()

	var r0 user.User
	if rf, ok := ret.Get(0).(func() user.User); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(user.User)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsBasicAuth provides a mock function with given fields:
func (_m *ServerRequestCtx) IsBasicAuth() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// ReadBody provides a mock function with given fields: body
func (_m *ServerRequestCtx) ReadBody(body interface{}) error {
	ret := _m.Called(body)

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(body)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenAuthentication provides a mock function with given fields:
func (_m *ServerRequestCtx) TokenAuthentication() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
