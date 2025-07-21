package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/mcpbus-io/mcpbus/config"
	"github.com/mcpbus-io/mcpbus/mcp"
)

var (
	flagConfFilePath string
	flagLogLevel     string
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	flag.StringVar(&flagConfFilePath, "config", "", "Path to MCPBus config file")
	flag.StringVar(&flagLogLevel, "loglevel", "info", "Log level, one of: trace, debug, info, warn, error, fatal, panic")
}

func main() {
	flag.Parse()

	// set log-level
	logLevel, err := log.ParseLevel(flagLogLevel)
	if err != nil {
		log.WithError(err).Fatal("Invalid flag 'loglevel'")
	}
	log.SetLevel(logLevel)

	// read the main config
	var configData []byte = nil
	if flagConfFilePath != "" {
		var err error
		configData, err = os.ReadFile(flagConfFilePath)
		if err != nil {
			log.WithError(err).Fatal("Error reading config file")
		}
	}

	conf, err := config.LoadConfig(configData)
	if err != nil {
		log.WithError(err).Fatal("Error parsing config file")
	}

	// start MCP server
	// https://modelcontextprotocol.io/specification/2025-03-26
	server, err := mcp.NewStreamableServer(conf)
	if err != nil {
		log.WithError(err).Fatal("Error creating server")
	}

	log.WithFields(log.Fields{
		"server_name":    mcp.ServerName,
		"server_version": mcp.ServerVersion,
		"addr":           conf.Addr,
		"port":           conf.Port,
		"mcp_end_point":  conf.McpEndpoint,
	}).Info("Starting MCP server")

	log.Fatal(server.Start())
}
