package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
)

type Handler interface {
	Initialize(ctx context.Context, params map[string]any) (InitializeResult, error)
	ListTools(ctx context.Context, cursor string) (ToolListResult, error)
	CallTool(ctx context.Context, name string, args map[string]any) (ToolCallResult, error)
	ListResources(ctx context.Context, cursor string) (ResourceListResult, error)
	ListResourceTemplates(ctx context.Context, cursor string) (ResourceTemplateListResult, error)
	ReadResource(ctx context.Context, uri string) (ResourceReadResult, error)
}

type Server struct {
	handler Handler
	in      *bufio.Scanner
	out     io.Writer
	writeMu sync.Mutex

	inflightMu sync.Mutex
	inflight   map[string]context.CancelFunc
}

func NewServer(handler Handler, in io.Reader, out io.Writer) *Server {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	return &Server{
		handler:  handler,
		in:       scanner,
		out:      out,
		inflight: map[string]context.CancelFunc{},
	}
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
		reqCtx, cancel := context.WithCancel(ctx)
		s.trackRequest(req.ID, cancel)
		go func(r Request, ctxReq context.Context) {
			defer s.untrackRequest(r.ID)
			resp := s.handleRequest(ctxReq, r)
			if ctxReq.Err() != nil {
				return
			}
			if err := s.writeResponse(resp); err != nil {
				log.Printf("mcp: write response failed: %v", err)
			}
		}(req, reqCtx)
	}
	if err := s.in.Err(); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleNotification(ctx context.Context, req Request) {
	switch req.Method {
	case "notifications/initialized", "initialized":
		return
	case "notifications/cancelled":
		reqID, ok := parseCancelRequestID(req.Params)
		if !ok {
			return
		}
		s.cancelRequest(reqID)
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
			return errorResponse(req.ID, rpcErrorCode(err), err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "tools/list":
		cursor, err := parseCursor(req.Params)
		if err != nil {
			return errorResponse(req.ID, ErrorInvalidParams, "invalid params", nil)
		}
		result, err := s.handler.ListTools(ctx, cursor)
		if err != nil {
			return errorResponse(req.ID, rpcErrorCode(err), err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
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
			return errorResponse(req.ID, rpcErrorCode(err), err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "resources/list":
		cursor, err := parseCursor(req.Params)
		if err != nil {
			return errorResponse(req.ID, ErrorInvalidParams, "invalid params", nil)
		}
		result, err := s.handler.ListResources(ctx, cursor)
		if err != nil {
			return errorResponse(req.ID, rpcErrorCode(err), err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "resources/templates/list":
		cursor, err := parseCursor(req.Params)
		if err != nil {
			return errorResponse(req.ID, ErrorInvalidParams, "invalid params", nil)
		}
		result, err := s.handler.ListResourceTemplates(ctx, cursor)
		if err != nil {
			return errorResponse(req.ID, rpcErrorCode(err), err.Error(), nil)
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}
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
			return errorResponse(req.ID, rpcErrorCode(err), err.Error(), nil)
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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

func rpcErrorCode(err error) int {
	var invalidParams *InvalidParamsError
	if errors.As(err, &invalidParams) {
		return ErrorInvalidParams
	}
	return ErrorInternal
}

func parseCursor(params any) (string, error) {
	if params == nil {
		return "", nil
	}
	raw, ok := params.(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid params")
	}
	if rawCursor, ok := raw["cursor"]; ok {
		switch v := rawCursor.(type) {
		case string:
			return v, nil
		default:
			return fmt.Sprint(v), nil
		}
	}
	return "", nil
}

func parseCancelRequestID(params any) (any, bool) {
	raw, ok := params.(map[string]any)
	if !ok || raw == nil {
		return nil, false
	}
	if id, ok := raw["requestId"]; ok {
		return id, true
	}
	if id, ok := raw["id"]; ok {
		return id, true
	}
	if id, ok := raw["request_id"]; ok {
		return id, true
	}
	return nil, false
}

func (s *Server) trackRequest(id any, cancel context.CancelFunc) {
	s.inflightMu.Lock()
	s.inflight[requestKey(id)] = cancel
	s.inflightMu.Unlock()
}

func (s *Server) untrackRequest(id any) {
	s.inflightMu.Lock()
	delete(s.inflight, requestKey(id))
	s.inflightMu.Unlock()
}

func (s *Server) cancelRequest(id any) {
	s.inflightMu.Lock()
	cancel := s.inflight[requestKey(id)]
	s.inflightMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func requestKey(id any) string {
	return fmt.Sprintf("%v", id)
}
