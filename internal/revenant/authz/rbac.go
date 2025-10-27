package authz

import (
	"fmt"
	"sync"
)

type Role string

const (
	RoleOperator Role = "operator"
	RoleManager  Role = "manager"
	RoleAuditor  Role = "auditor"
	RoleAdmin    Role = "admin"
)

type Permission string

const (
	PermissionViewTasks     Permission = "view_tasks"
	PermissionCreateTask    Permission = "create_task"
	PermissionApproveTask   Permission = "approve_task"
	PermissionCancelTask    Permission = "cancel_task"
	PermissionRunPlaybook   Permission = "run_playbook"
	PermissionManageUsers   Permission = "manage_users"
	PermissionViewAuditLog  Permission = "view_audit_log"
	PermissionManageConfig  Permission = "manage_config"
)

type User struct {
	ID          string
	Username    string
	Roles       []Role
	Permissions []Permission
}

type RBAC struct {
	mu          sync.RWMutex
	users       map[string]*User
	rolePerms   map[Role][]Permission
}

func NewRBAC() *RBAC {
	rbac := &RBAC{
		users:     make(map[string]*User),
		rolePerms: make(map[Role][]Permission),
	}

	rbac.rolePerms[RoleOperator] = []Permission{
		PermissionViewTasks,
		PermissionCreateTask,
	}

	rbac.rolePerms[RoleManager] = []Permission{
		PermissionViewTasks,
		PermissionCreateTask,
		PermissionApproveTask,
		PermissionCancelTask,
		PermissionRunPlaybook,
	}

	rbac.rolePerms[RoleAuditor] = []Permission{
		PermissionViewTasks,
		PermissionViewAuditLog,
	}

	rbac.rolePerms[RoleAdmin] = []Permission{
		PermissionViewTasks,
		PermissionCreateTask,
		PermissionApproveTask,
		PermissionCancelTask,
		PermissionRunPlaybook,
		PermissionManageUsers,
		PermissionViewAuditLog,
		PermissionManageConfig,
	}

	return rbac
}

func (r *RBAC) AddUser(user *User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.users[user.ID]; exists {
		return fmt.Errorf("user already exists: %s", user.ID)
	}

	r.users[user.ID] = user
	return nil
}

func (r *RBAC) GetUser(userID string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	return user, nil
}

func (r *RBAC) HasPermission(userID string, permission Permission) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[userID]
	if !exists {
		return false
	}

	for _, perm := range user.Permissions {
		if perm == permission {
			return true
		}
	}

	for _, role := range user.Roles {
		if perms, ok := r.rolePerms[role]; ok {
			for _, perm := range perms {
				if perm == permission {
					return true
				}
			}
		}
	}

	return false
}

func (r *RBAC) Authorize(userID string, permission Permission) error {
	if !r.HasPermission(userID, permission) {
		return fmt.Errorf("user %s does not have permission: %s", userID, permission)
	}
	return nil
}

func (r *RBAC) AssignRole(userID string, role Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, exists := r.users[userID]
	if !exists {
		return fmt.Errorf("user not found: %s", userID)
	}

	for _, existingRole := range user.Roles {
		if existingRole == role {
			return nil
		}
	}

	user.Roles = append(user.Roles, role)
	return nil
}

func (r *RBAC) RevokeRole(userID string, role Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, exists := r.users[userID]
	if !exists {
		return fmt.Errorf("user not found: %s", userID)
	}

	for i, existingRole := range user.Roles {
		if existingRole == role {
			user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
			return nil
		}
	}

	return nil
}

func (r *RBAC) ListUsers() []*User {
	r.mu.RLock()
	defer r.mu.RUnlock()

	users := make([]*User, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}

	return users
}
