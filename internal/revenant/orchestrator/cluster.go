package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

type ClusterNode struct {
	ID            string
	Address       string
	IsLeader      bool
	Health        string
	LastHeartbeat time.Time
	TasksRunning  atomic.Int64
	TasksCompleted atomic.Int64
	CPUUsage      float64
	MemoryUsage   float64
}

type ClusterCoordinator struct {
	logger      *logging.Logger
	localNode   *ClusterNode
	nodes       map[string]*ClusterNode
	mu          sync.RWMutex
	
	taskQueue   chan *Task
	localEngine *Engine
	
	isLeader    atomic.Bool
	leaderID    atomic.Value
	
	heartbeatInterval time.Duration
	healthCheckInterval time.Duration
	
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type TaskDistributor struct {
	coordinator *ClusterCoordinator
	strategy    string
}

func NewClusterCoordinator(nodeID, address string, logger *logging.Logger, localEngine *Engine) *ClusterCoordinator {
	ctx, cancel := context.WithCancel(context.Background())
	
	cc := &ClusterCoordinator{
		logger: logger,
		localNode: &ClusterNode{
			ID:            nodeID,
			Address:       address,
			Health:        "healthy",
			LastHeartbeat: time.Now(),
		},
		nodes:               make(map[string]*ClusterNode),
		taskQueue:           make(chan *Task, 10000),
		localEngine:         localEngine,
		heartbeatInterval:   5 * time.Second,
		healthCheckInterval: 10 * time.Second,
		ctx:                 ctx,
		cancel:              cancel,
	}
	
	cc.nodes[nodeID] = cc.localNode
	
	return cc
}

func (cc *ClusterCoordinator) Start() error {
	cc.logger.Info("Starting cluster coordinator",
		logging.WithExtra("node_id", cc.localNode.ID),
		logging.WithExtra("address", cc.localNode.Address),
	)

	cc.wg.Add(1)
	go cc.heartbeatLoop()

	cc.wg.Add(1)
	go cc.healthCheckLoop()

	cc.wg.Add(1)
	go cc.taskDistributionLoop()

	cc.electLeader()

	return nil
}

func (cc *ClusterCoordinator) Stop() {
	cc.logger.Info("Stopping cluster coordinator")
	cc.cancel()
	cc.wg.Wait()
}

func (cc *ClusterCoordinator) heartbeatLoop() {
	defer cc.wg.Done()

	ticker := time.NewTicker(cc.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cc.ctx.Done():
			return
		case <-ticker.C:
			cc.sendHeartbeat()
		}
	}
}

func (cc *ClusterCoordinator) sendHeartbeat() {
	cc.mu.Lock()
	cc.localNode.LastHeartbeat = time.Now()
	cc.localNode.TasksRunning.Store(int64(len(cc.taskQueue)))
	cc.mu.Unlock()

	cc.logger.Debug("Heartbeat sent",
		logging.WithExtra("node_id", cc.localNode.ID),
		logging.WithExtra("tasks_running", cc.localNode.TasksRunning.Load()),
	)
}

func (cc *ClusterCoordinator) healthCheckLoop() {
	defer cc.wg.Done()

	ticker := time.NewTicker(cc.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cc.ctx.Done():
			return
		case <-ticker.C:
			cc.checkNodesHealth()
		}
	}
}

func (cc *ClusterCoordinator) checkNodesHealth() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	now := time.Now()
	unhealthyNodes := make([]string, 0)

	for nodeID, node := range cc.nodes {
		if nodeID == cc.localNode.ID {
			continue
		}

		if now.Sub(node.LastHeartbeat) > 30*time.Second {
			node.Health = "unhealthy"
			unhealthyNodes = append(unhealthyNodes, nodeID)
		}
	}

	if len(unhealthyNodes) > 0 {
		cc.logger.Warning("Detected unhealthy nodes",
			logging.WithExtra("count", len(unhealthyNodes)),
		)

		if cc.isLeader.Load() {
			cc.electLeader()
		}
	}
}

func (cc *ClusterCoordinator) taskDistributionLoop() {
	defer cc.wg.Done()

	for {
		select {
		case <-cc.ctx.Done():
			return
		case task := <-cc.taskQueue:
			cc.distributeTask(task)
		}
	}
}

func (cc *ClusterCoordinator) distributeTask(task *Task) {
	if !cc.isLeader.Load() {
		cc.forwardToLeader(task)
		return
	}

	targetNode := cc.selectNode()
	
	if targetNode.ID == cc.localNode.ID {
		cc.localEngine.SubmitTask(task)
	} else {
		cc.forwardToNode(targetNode, task)
	}
}

func (cc *ClusterCoordinator) selectNode() *ClusterNode {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	var bestNode *ClusterNode
	minLoad := int64(1000000)

	for _, node := range cc.nodes {
		if node.Health != "healthy" {
			continue
		}

		load := node.TasksRunning.Load()
		if load < minLoad {
			minLoad = load
			bestNode = node
		}
	}

	if bestNode == nil {
		bestNode = cc.localNode
	}

	return bestNode
}

func (cc *ClusterCoordinator) forwardToNode(node *ClusterNode, task *Task) {
	cc.logger.Debug("Forwarding task to node",
		logging.WithExtra("task_id", task.ID),
		logging.WithExtra("node_id", node.ID),
	)
}

func (cc *ClusterCoordinator) forwardToLeader(task *Task) {
	leaderID := cc.leaderID.Load()
	if leaderID == nil {
		cc.localEngine.SubmitTask(task)
		return
	}

	cc.logger.Debug("Forwarding task to leader",
		logging.WithExtra("task_id", task.ID),
		logging.WithExtra("leader_id", leaderID),
	)
}

func (cc *ClusterCoordinator) electLeader() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	var leader *ClusterNode
	for _, node := range cc.nodes {
		if node.Health != "healthy" {
			continue
		}

		if leader == nil || node.ID < leader.ID {
			leader = node
		}
	}

	if leader == nil {
		leader = cc.localNode
	}

	wasLeader := cc.isLeader.Load()
	isLeaderNow := leader.ID == cc.localNode.ID

	cc.isLeader.Store(isLeaderNow)
	cc.leaderID.Store(leader.ID)
	leader.IsLeader = true

	if !wasLeader && isLeaderNow {
		cc.logger.Info("Became cluster leader",
			logging.WithExtra("node_id", cc.localNode.ID),
		)
	} else if wasLeader && !isLeaderNow {
		cc.logger.Info("Lost cluster leadership",
			logging.WithExtra("new_leader", leader.ID),
		)
	}
}

func (cc *ClusterCoordinator) SubmitTask(task *Task) error {
	select {
	case cc.taskQueue <- task:
		return nil
	default:
		return fmt.Errorf("cluster task queue full")
	}
}

func (cc *ClusterCoordinator) RegisterNode(node *ClusterNode) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.nodes[node.ID] = node
	cc.logger.Info("Node registered",
		logging.WithExtra("node_id", node.ID),
		logging.WithExtra("address", node.Address),
	)

	cc.electLeader()
}

func (cc *ClusterCoordinator) UnregisterNode(nodeID string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	delete(cc.nodes, nodeID)
	cc.logger.Info("Node unregistered",
		logging.WithExtra("node_id", nodeID),
	)

	if cc.leaderID.Load() == nodeID {
		cc.electLeader()
	}
}

func (cc *ClusterCoordinator) GetClusterStats() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	totalNodes := len(cc.nodes)
	healthyNodes := 0
	totalTasks := int64(0)

	for _, node := range cc.nodes {
		if node.Health == "healthy" {
			healthyNodes++
		}
		totalTasks += node.TasksRunning.Load()
	}

	return map[string]interface{}{
		"total_nodes":   totalNodes,
		"healthy_nodes": healthyNodes,
		"is_leader":     cc.isLeader.Load(),
		"leader_id":     cc.leaderID.Load(),
		"total_tasks":   totalTasks,
	}
}

func (cc *ClusterCoordinator) IsLeader() bool {
	return cc.isLeader.Load()
}

func (cc *ClusterCoordinator) GetLeaderID() string {
	leaderID := cc.leaderID.Load()
	if leaderID == nil {
		return ""
	}
	return leaderID.(string)
}
