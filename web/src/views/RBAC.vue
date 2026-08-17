<template>
  <div class="rbac-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>用户与权限管理</span>
          <el-button type="primary" @click="openAddDialog">添加用户</el-button>
        </div>
      </template>

      <el-table :data="pagedUsers" stripe v-loading="loading">
        <el-table-column prop="username" label="用户名" width="150" />
        <el-table-column prop="role" label="角色" width="120">
          <template #default="{ row }">
            <el-tag :type="roleTagType(row.role)">{{ roleLabel(row.role) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="tenant_id" label="租户" width="120" />
        <el-table-column prop="permissions" label="权限">
          <template #default="{ row }">
            <el-tag v-for="p in (row.permissions || getPermsForRole(row.role))" :key="p" size="small" class="perm-tag">{{ permLabel(p) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="250">
          <template #default="{ row }">
            <el-button size="small" @click="openEditDialog(row)">编辑</el-button>
            <el-button size="small" type="warning" @click="openResetPasswordDialog(row)">重置密码</el-button>
            <el-button size="small" type="danger" @click="deleteUser(row)" :disabled="row.role === 'owner'">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="users.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="users.length"
          layout="total, sizes, prev, pager, next"
        />
      </div>
    </el-card>

    <el-card class="role-matrix">
      <template #header>角色权限矩阵</template>
      <el-table :data="roleMatrix" stripe>
        <el-table-column prop="role" label="角色" width="120" />
        <el-table-column prop="view" label="查看" width="80">
          <template #default="{ row }">
            <el-icon v-if="row.view" color="green"><Check /></el-icon>
            <el-icon v-else color="#f56c6c"><Close /></el-icon>
          </template>
        </el-table-column>
        <el-table-column prop="operate" label="操作" width="80">
          <template #default="{ row }">
            <el-icon v-if="row.operate" color="green"><Check /></el-icon>
            <el-icon v-else color="#f56c6c"><Close /></el-icon>
          </template>
        </el-table-column>
        <el-table-column prop="configure" label="配置" width="80">
          <template #default="{ row }">
            <el-icon v-if="row.configure" color="green"><Check /></el-icon>
            <el-icon v-else color="#f56c6c"><Close /></el-icon>
          </template>
        </el-table-column>
        <el-table-column prop="audit" label="审计" width="80">
          <template #default="{ row }">
            <el-icon v-if="row.audit" color="green"><Check /></el-icon>
            <el-icon v-else color="#f56c6c"><Close /></el-icon>
          </template>
        </el-table-column>
        <el-table-column prop="manage" label="管理" width="80">
          <template #default="{ row }">
            <el-icon v-if="row.manage" color="green"><Check /></el-icon>
            <el-icon v-else color="#f56c6c"><Close /></el-icon>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 添加用户对话框 -->
    <el-dialog v-model="showAddUser" title="添加用户" width="460px">
      <el-form :model="newUser" label-width="80px">
        <el-form-item label="用户名">
          <el-input v-model="newUser.username" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input
            v-model="newUser.password"
            type="password"
            show-password
            placeholder="至少 6 位密码"
          />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input
            v-model="newUser.confirmPassword"
            type="password"
            show-password
            placeholder="请再次输入密码"
          />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="newUser.role">
            <el-option label="所有者" value="owner" />
            <el-option label="管理员" value="admin" />
            <el-option label="操作员" value="operator" />
            <el-option label="查看者" value="viewer" />
            <el-option label="审计员" value="auditor" />
          </el-select>
        </el-form-item>
        <el-form-item label="租户ID">
          <el-input v-model="newUser.tenant_id" placeholder="default" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddUser = false">取消</el-button>
        <el-button type="primary" @click="addUser" :loading="submitting">确定</el-button>
      </template>
    </el-dialog>

    <!-- 编辑用户对话框 -->
    <el-dialog v-model="showEditUser" title="编辑用户" width="460px">
      <el-form :model="editUserData" label-width="80px">
        <el-form-item label="用户名">
          <el-input v-model="editUserData.username" disabled />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="editUserData.role">
            <el-option label="所有者" value="owner" />
            <el-option label="管理员" value="admin" />
            <el-option label="操作员" value="operator" />
            <el-option label="查看者" value="viewer" />
            <el-option label="审计员" value="auditor" />
          </el-select>
        </el-form-item>
        <el-form-item label="租户ID">
          <el-input v-model="editUserData.tenant_id" />
        </el-form-item>
      </el-form>
      <el-alert type="info" :closable="false" show-icon style="margin-top: 10px">
        如需修改密码，请使用「重置密码」功能。
      </el-alert>
      <template #footer>
        <el-button @click="showEditUser = false">取消</el-button>
        <el-button type="primary" @click="saveEditUser" :loading="submitting">保存</el-button>
      </template>
    </el-dialog>

    <!-- 重置密码对话框 -->
    <el-dialog v-model="showResetPassword" title="重置密码" width="460px">
      <el-form :model="resetPasswordData" label-width="80px">
        <el-form-item label="用户名">
          <el-input v-model="resetPasswordData.username" disabled />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input
            v-model="resetPasswordData.newPassword"
            type="password"
            show-password
            placeholder="至少 6 位新密码"
          />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input
            v-model="resetPasswordData.confirmPassword"
            type="password"
            show-password
            placeholder="请再次输入新密码"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showResetPassword = false">取消</el-button>
        <el-button type="warning" @click="confirmResetPassword" :loading="submitting">确认重置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { Check, Close } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'
import dayjs from 'dayjs'

const users = ref([])
const loading = ref(false)
const submitting = ref(false)

const roleMatrix = ref([
  { role: '所有者', view: true, operate: true, configure: true, audit: true, manage: true },
  { role: '管理员', view: true, operate: true, configure: true, audit: true, manage: false },
  { role: '操作员', view: true, operate: true, configure: false, audit: false, manage: false },
  { role: '查看者', view: true, operate: false, configure: false, audit: false, manage: false },
  { role: '审计员', view: true, operate: false, configure: false, audit: true, manage: false },
])

const showAddUser = ref(false)
const showEditUser = ref(false)
const showResetPassword = ref(false)
const newUser = reactive({ username: '', password: '', confirmPassword: '', role: 'operator', tenant_id: 'default' })
const editUserData = reactive({ id: 0, username: '', role: '', tenant_id: '' })
const resetPasswordData = reactive({ id: 0, username: '', newPassword: '', confirmPassword: '' })
const currentPage = ref(1)
const pageSize = ref(10)

const pagedUsers = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return users.value.slice(start, start + pageSize.value)
})

function roleLabel(role) {
  const labels = { owner: '所有者', admin: '管理员', operator: '操作员', viewer: '查看者', auditor: '审计员' }
  return labels[role] || role
}

function permLabel(perm) {
  const labels = { view: '查看', operate: '操作', configure: '配置', audit: '审计', manage: '管理' }
  return labels[perm] || perm
}

function roleTagType(role) {
  const types = { owner: 'danger', admin: 'warning', operator: 'success', viewer: 'info', auditor: '' }
  return types[role] || 'info'
}

function getPermsForRole(role) {
  const permMap = {
    owner: ['view', 'operate', 'configure', 'audit', 'manage'],
    admin: ['view', 'operate', 'configure', 'audit'],
    operator: ['view', 'operate'],
    viewer: ['view'],
    auditor: ['view', 'audit'],
  }
  return permMap[role] || ['view']
}

async function loadUsers() {
  loading.value = true
  try {
    const resp = await axios.get('/api/rbac/users')
    users.value = resp.data.users || []
  } catch (e) {
    // 降级：使用本地数据
    users.value = [
      { id: 0, username: 'admin', role: 'owner', tenant_id: 'default', permissions: ['view', 'operate', 'configure', 'audit', 'manage'] },
    ]
  } finally {
    loading.value = false
  }
}

function openAddDialog() {
  newUser.username = ''
  newUser.password = ''
  newUser.confirmPassword = ''
  newUser.role = 'operator'
  newUser.tenant_id = 'default'
  showAddUser.value = true
}

async function addUser() {
  if (!newUser.username) { ElMessage.warning('用户名不能为空'); return }
  if (!newUser.password) { ElMessage.warning('密码不能为空'); return }
  if (newUser.password.length < 6) { ElMessage.warning('密码长度不能少于 6 位'); return }
  if (newUser.password !== newUser.confirmPassword) { ElMessage.warning('两次输入的密码不一致'); return }

  submitting.value = true
  try {
    await axios.post('/api/rbac/users', {
      username: newUser.username,
      password: newUser.password,
      role: newUser.role,
      tenant_id: newUser.tenant_id,
    })
    ElMessage.success('用户添加成功')
    showAddUser.value = false
    await loadUsers()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '添加失败')
  } finally {
    submitting.value = false
  }
}

function openEditDialog(row) {
  editUserData.id = row.id
  editUserData.username = row.username
  editUserData.role = row.role
  editUserData.tenant_id = row.tenant_id
  showEditUser.value = true
}

async function saveEditUser() {
  submitting.value = true
  try {
    await axios.put(`/api/rbac/users/${editUserData.id}`, {
      role: editUserData.role,
      tenant_id: editUserData.tenant_id,
    })
    ElMessage.success('用户修改成功')
    showEditUser.value = false
    await loadUsers()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '修改失败')
  } finally {
    submitting.value = false
  }
}

function openResetPasswordDialog(row) {
  resetPasswordData.id = row.id
  resetPasswordData.username = row.username
  resetPasswordData.newPassword = ''
  resetPasswordData.confirmPassword = ''
  showResetPassword.value = true
}

async function confirmResetPassword() {
  if (!resetPasswordData.newPassword) { ElMessage.warning('新密码不能为空'); return }
  if (resetPasswordData.newPassword.length < 6) { ElMessage.warning('密码长度不能少于 6 位'); return }
  if (resetPasswordData.newPassword !== resetPasswordData.confirmPassword) { ElMessage.warning('两次输入的密码不一致'); return }

  submitting.value = true
  try {
    await axios.post(`/api/rbac/users/${resetPasswordData.id}/reset-password`, {
      new_password: resetPasswordData.newPassword,
    })
    ElMessage.success('密码重置成功')
    showResetPassword.value = false
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '重置失败')
  } finally {
    submitting.value = false
  }
}

async function deleteUser(row) {
  if (row.role === 'owner') {
    ElMessage.warning('所有者账户不可删除')
    return
  }
  try {
    await ElMessageBox.confirm(
      `确认删除用户「${row.username}」？此操作不可逆！`,
      '删除用户',
      { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' }
    )
  } catch {
    return
  }

  try {
    await axios.delete(`/api/rbac/users/${row.id}`)
    ElMessage.success('用户删除成功')
    await loadUsers()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '删除失败')
  }
}

// 初始化加载
loadUsers()
</script>

<style scoped>
.rbac-page { padding: 20px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.role-matrix { margin-top: 20px; }
.perm-tag { margin-right: 4px; }
</style>
