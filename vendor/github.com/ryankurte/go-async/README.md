# go-async-mgr

[![Documentation](https://img.shields.io/badge/docs-godoc-blue.svg)](https://godoc.org/github.com/ryankurte/go-async-mgr)
[![GitHub tag](https://img.shields.io/github/tag/ryankurte/go-async-mgr.svg)](https://github.com/ryankurte/go-async-mgr)
[![Build Status](https://travis-ci.org/ryankurte/go-async-mgr.svg?branch=master)](https://travis-ci.org/ryankurte/go-async-mgr)

A quick and dirty wrapper for managing communication between parallel asynchronous services.

## Usage

```go


import(
    "gopkg.in/ryankurte/go-async-mgr.v1"
)

// Create a service manager
// This requires that you specify the global input channel size
sm := async.NewServiceManager(32)

// Create async service instances around RunnableInterfaces
// Again, this requires that you specify the per-service input channel size
s1 := async.NewAsyncService(&FakeWorker{id: 1}, 2)
s2 := async.NewAsyncService(&FakeWorker{id: 2}, 2)

// Bind the services into the manager
sm.BindService(&s1)
sm.BindService(&s2)

// Run the service manager
// This launches all worker threads automatically
sm.Run()

// Send some events to the service manager
// These will be distributed to all workers (in parallel)
sm.SendEvent("test")

...

// Shut down the service manager
// This will wait and exit all async services
sm.Exit()

```