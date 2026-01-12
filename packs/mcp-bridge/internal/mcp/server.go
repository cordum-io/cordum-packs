package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
)

type Handler interface {
	Initialize(ctx context.Context, params map[string]any) (InitializeResult, error)
	ListTools(ctx context.Context) ([]Tool, error)
	CallTool(ctx context.Context, name string, args map[string]any) (ToolCallResult, error)
	ListResources(ctx context.Context) ([]Resource, error)
	ReadResource(ctx context.Context, uri string) (ResourceReadResult, error)
}

type Server struct {
	handler Handler
	in      *bufio.Scanner
	out     io.Writer
}

func NewServer(handler Handler, in io.Reader, out io.Writer) *Server {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	return &Server{handler: handler, in: scanner, out: out}
}

func (s *Server) Run(ctx context.Context) error {
	for s.in.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := strings.TrimSpace(s.in.Text())
		if line == "" {
			continue
		}
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = s.writeError(nil, ErrorParse, "invalid json", err.Error())
			continue
		}
		if req.JSONRPC == "" {
			req.JSONRPC = "2.0"
		}
		if req.ID == nil {
			// Notification: no response required.
			s.handleNotification(ctx, req)
			continue
		}
		resp := s.handleRequest(ctx, req)
		if err := s.writeResponse(resp); err != nil {
			log.Printf("mcp: write response failed: %v", err)
		}
	}
	if err := s.in.Err(); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleNotification(ctx context.Context, req Request) {
	switch req.Method {
	case "initialized":
		return
	default:
		return
	}
}

func (s *Server) handleRequest(ctx context.Context, req Request) Response {
	switch req.Method {
	case "initialize":
		params := map[string]any{}
		if req.Params != nil {
			if decoded, ok := req.Params.(map[string]any); ok {
				params = decoded
			} else {
				return errorResponse(req.ID, ErrorInvalidParams, "invalid params", nil)
			}
		}
		result, err := s.handler.Initialize(ctx, params)
		if err != nil {
			return errorResponse(req.ID, ErrorInternal, err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "tools/list":
		tools, err := s.handler.ListTools(ctx)
		if err != nil {
			return errorResponse(req.ID, ErrorInternal, err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: ToolListResult{Tools: tools}}
	case "tools/call":
		params, ok := req.Params.(map[string]any)
		if !ok {
			return errorResponse(req.ID, ErrorInvalidParams, "invalid params", nil)
		}
		name, _ := params["name"].(string)
		args := map[string]any{}
		if rawArgs, ok := params["arguments"].(map[string]any); ok {
			args = rawArgs
		}
		if name == "" {
			return errorResponse(req.ID, ErrorInvalidParams, "tool name required", nil)
		}
		result, err := s.handler.CallTool(ctx, name, args)
		if err != nil {
			return errorResponse(req.ID, ErrorInternal, err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "resources/list":
		resources, err := s.handler.ListResources(ctx)
		if err != nil {
			return errorResponse(req.ID, ErrorInternal, err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: ResourceListResult{Resources: resources}}
	case "resources/read":
		params, ok := req.Params.(map[string]any)
		if !ok {
			return errorResponse(req.ID, ErrorInvalidParams, "invalid params", nil)
		}
		uri, _ := params["uri"].(string)
		if uri == "" {
			return errorResponse(req.ID, ErrorInvalidParams, "uri required", nil)
		}
		result, err := s.handler.ReadResource(ctx, uri)
		if err != nil {
			return errorResponse(req.ID, ErrorInternal, err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "ping":
		return Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	default:
		return errorResponse(req.ID, ErrorMethodNotFound, fmt.Sprintf("unknown method %s", req.Method), nil)
	}
}

func (s *Server) writeResponse(resp Response) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(s.out, "%s\n", payload)
	return err
}

func (s *Server) writeError(id any, code int, message string, data any) error {
	resp := errorResponse(id, code, message, data)
	return s.writeResponse(resp)
}

func errorResponse(id any, code int, message string, data any) Response {
	return Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}
