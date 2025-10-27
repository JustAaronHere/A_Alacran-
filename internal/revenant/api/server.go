package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/authz"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/orchestrator"
)

type Server struct {
	logger  *logging.Logger
	engine  *orchestrator.Engine
	rbac    *authz.RBAC
	addr    string
	server  *http.Server
}

func NewServer(addr string, logger *logging.Logger, engine *orchestrator.Engine, rbac *authz.RBAC) *Server {
	return &Server{
		logger: logger,
		engine: engine,
		rbac:   rbac,
		addr:   addr,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/tasks", s.handleTasks)
	mux.HandleFunc("/api/v1/tasks/", s.handleTask)
	mux.HandleFunc("/api/v1/approvals", s.handleApprovals)
	mux.HandleFunc("/api/v1/approvals/", s.handleApproval)
	mux.HandleFunc("/api/v1/stats", s.handleStats)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s.logger.Info("Starting API server", logging.WithExtra("addr", s.addr))

	return s.server.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping API server")
	return s.server.Shutdown(ctx)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		s.logger.Debug("API request",
			logging.WithExtra("method", r.Method),
			logging.WithExtra("path", r.URL.Path),
			logging.WithExtra("remote", r.RemoteAddr),
		)

		next.ServeHTTP(w, r)

		s.logger.Debug("API request completed",
			logging.WithExtra("method", r.Method),
			logging.WithExtra("path", r.URL.Path),
			logging.WithExtra("duration", time.Since(start).String()),
		)
	})
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tasks := s.engine.ListTasks(nil)
		s.respondJSON(w, http.StatusOK, tasks)
	case http.MethodPost:
		var task orchestrator.Task
		if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
			s.respondError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if err := s.engine.SubmitTask(&task); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.respondJSON(w, http.StatusCreated, task)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Path[len("/api/v1/tasks/"):]

	switch r.Method {
	case http.MethodGet:
		task, err := s.engine.GetTask(taskID)
		if err != nil {
			s.respondError(w, http.StatusNotFound, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, task)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		approvals := s.engine.GetPendingApprovals()
		s.respondJSON(w, http.StatusOK, approvals)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleApproval(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Path[len("/api/v1/approvals/"):]

	switch r.Method {
	case http.MethodPost:
		var response orchestrator.ApprovalResponse
		if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
			s.respondError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		var err error
		if response.Approved {
			err = s.engine.ApproveTask(taskID, response.ApprovedBy, response.Reason)
		} else {
			err = s.engine.RejectTask(taskID, response.ApprovedBy, response.Reason)
		}

		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.respondJSON(w, http.StatusOK, map[string]string{"status": "success"})
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	stats := s.engine.Stats()
	s.respondJSON(w, http.StatusOK, stats)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready"))
}

func (s *Server) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) respondError(w http.ResponseWriter, status int, message string) {
	s.respondJSON(w, status, map[string]string{"error": message})
}
