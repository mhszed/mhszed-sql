<template>
  <div class="page-wrap">
    <h2 class="page-title">审计日志</h2>

    <el-card class="panel-card">
      <!-- 筛选栏 -->
      <div class="filter-bar">
        <el-input v-model="q.action" placeholder="动作（如 login/review_submit）" clearable
                  style="width: 220px" @change="reload" />
        <el-input v-model="q.resource_type" placeholder="资源类型（task/vulnerability…）" clearable
                  style="width: 220px" @change="reload" />
        <el-button type="primary" @click="reload">查询</el-button>
        <el-button type="danger" plain :disabled="!selected.length" @click="batchDel">
          删除选中{{ selected.length ? `（${selected.length}）` : '' }}
        </el-button>
        <el-button type="danger" :loading="clearing" @click="clearAll">清空日志</el-button>
        <span class="hint">删除会打断哈希链，仅建议清理测试噪音</span>
      </div>

      <el-table :data="items" v-loading="loading" stripe @selection-change="onSelect">
        <el-table-column type="selection" width="42" />
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column label="时间" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作人" width="110">
          <template #default="{ row }">
            <span v-if="row.username">{{ row.username }}</span>
            <span v-else-if="row.user_id != null">#{{ row.user_id }}</span>
            <span v-else class="dim">系统</span>
          </template>
        </el-table-column>
        <el-table-column prop="action" label="动作" width="140">
          <template #default="{ row }">
            <el-tag :type="actionTag(row.action)" size="small">{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="资源" width="180">
          <template #default="{ row }">
            <span v-if="row.resource_type">
              {{ row.resource_type }}<span v-if="row.resource_id"> #{{ row.resource_id }}</span>
            </span>
            <span v-else class="dim">-</span>
          </template>
        </el-table-column>
        <el-table-column label="详情">
          <template #default="{ row }">
            <span class="ellipsis detail" :title="row.detail">{{ row.detail || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="danger" text @click="delOne(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
                     layout="total, prev, pager, next" @current-change="load" />
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import http from '../api/http'

const items = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 15
const loading = ref(false)
const selected = ref([])
const q = reactive({ action: '', resource_type: '' })

function reload() { page.value = 1; load() }
function onSelect(rows) { selected.value = rows }

async function load() {
  loading.value = true
  try {
    const params = { page: page.value, page_size: pageSize }
    if (q.action) params.action = q.action
    if (q.resource_type) params.resource_type = q.resource_type
    const { data } = await http.get('/audit', { params })
    items.value = data.items
    total.value = data.total
  } finally { loading.value = false }
}

async function delOne(row) {
  await ElMessageBox.confirm(`删除审计日志 #${row.id}？此操作会打断哈希链。`, '删除确认', { type: 'warning' })
  await http.delete(`/audit/${row.id}`)
  ElMessage.success('已删除')
  load()
}

async function batchDel() {
  const ids = selected.value.map(r => r.id)
  if (!ids.length) return
  await ElMessageBox.confirm(`删除选中的 ${ids.length} 条审计日志？`, '批量删除', { type: 'warning' })
  await http.post('/audit/purge', { ids })
  ElMessage.success(`已删除 ${ids.length} 条`)
  selected.value = []
  load()
}

const clearing = ref(false)
async function clearAll() {
  try {
    await ElMessageBox.confirm(
      '清空全部审计日志？不可恢复，且会打断哈希链；清空动作本身会留下一条记录。',
      '清空日志', { type: 'warning', confirmButtonText: '确认清空' })
  } catch { return }                      // 用户取消
  clearing.value = true
  try {
    const { data } = await http.post('/audit/purge', { all: true })
    ElMessage.success(`已清空 ${data.deleted ?? 0} 条审计日志`)
    selected.value = []
    reload()
  } finally { clearing.value = false }
}

function fmtTime(iso) {
  // 后端存 UTC ISO（带 Z）：必须真转本地时区。旧实现只做字符串替换，
  // UI 显示 UTC 比本地早 8 小时，看起来像"在测昨天的旧数据"
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function actionTag(a) {
  if (a?.includes('review')) return 'warning'
  if (a?.includes('kb_edit') || a?.includes('config')) return 'success'
  if (a?.includes('login') || a?.includes('logout')) return 'info'
  if (a?.includes('delete') || a?.includes('purge')) return 'danger'
  return 'info'   // Element Plus 不接受空字符串，空值会刷一屏 Vue warn
}

onMounted(load)
</script>

<style scoped>
.filter-bar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }
.hint { color: var(--text-dim); font-size: 12px; margin-left: auto; }
.dim { color: var(--text-dim); }
.mono { font-family: Consolas, monospace; }
.detail { display: block; max-width: 320px; }
</style>
