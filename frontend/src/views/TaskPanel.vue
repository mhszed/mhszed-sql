<template>
  <div class="page-wrap">
    <h2 class="page-title">任务面板</h2>

    <el-card class="panel-card">
      <div class="toolbar">
        <el-select v-model="statusFilter" placeholder="状态筛选" clearable style="width: 150px"
                   @change="reload">
          <el-option v-for="s in STATUSES" :key="s" :label="s" :value="s" />
        </el-select>
        <el-button type="primary" @click="openCreate">＋ 新建任务</el-button>
        <el-button type="danger" plain :disabled="!selected.length" @click="batchDel">
          批量删除{{ selected.length ? `（${selected.length}）` : '' }}
        </el-button>
        <span class="hint">流程：collecting → scanning → review（人工研判）→ done</span>
      </div>

      <el-table :data="items" v-loading="loading" stripe
                @selection-change="onSelect">
        <el-table-column type="selection" width="42"
                         :selectable="(row) => !['collecting', 'scanning'].includes(row.status)" />
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="name" label="任务名" width="160">
          <template #default="{ row }">
            <el-link type="primary" @click="goCollect(row)">{{ row.name }}</el-link>
          </template>
        </el-table-column>
        <el-table-column prop="target" label="目标" min-width="200">
          <template #default="{ row }">
            <el-link type="primary" class="ellipsis" :title="row.target" @click="goCollect(row)">
              {{ row.target }}
            </el-link>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="statusTag(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="进度" width="110">
          <template #default="{ row }">
            <span v-if="row.progress" class="mono dim">
              {{ row.progress.done ?? 0 }}/{{ row.progress.total ?? '?' }}
            </span>
            <span v-else class="dim">-</span>
          </template>
        </el-table-column>
        <el-table-column label="采集模式" width="90">
          <template #default="{ row }">{{ row.collect_mode }}</template>
        </el-table-column>
        <el-table-column label="创建时间" width="160">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="300" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="success" v-if="canStart(row)"
                       @click="start(row)">启动</el-button>
            <el-button size="small" type="warning" v-if="canStop(row)"
                       @click="stop(row)">终止</el-button>
            <el-button size="small" v-if="row.status === 'review'"
                       type="primary" @click="goReview(row)">去研判</el-button>
            <el-button size="small" type="primary" plain @click="goCollect(row)">采集</el-button>
            <el-button size="small" @click="openLogs(row)">日志</el-button>
            <el-button size="small" type="danger" plain
                       v-if="!['collecting', 'scanning'].includes(row.status)"
                       @click="del(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
                     layout="total, prev, pager, next" @current-change="load" />
    </el-card>

    <!-- 新建任务 -->
    <el-dialog v-model="dlg" title="新建任务" width="560">
      <el-form :model="form" label-width="96px">
        <el-form-item label="任务名">
          <el-input v-model="form.name" maxlength="128" placeholder="例：某站全链路测试" />
        </el-form-item>
        <el-form-item label="目标 URL">
          <el-input v-model="form.target" placeholder="http://example.com/（须在授权范围内）" />
        </el-form-item>
        <el-form-item label="采集方式">
          <el-radio-group v-model="form.collect_mode">
            <el-radio value="both">静态爬虫 + Burp</el-radio>
            <el-radio value="static">仅静态爬虫</el-radio>
            <el-radio value="burp">仅 Burp 流量</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-divider content-position="left">扫描配置</el-divider>
        <el-form-item label="探测强度">
          <el-radio-group v-model="cfg.intensity">
            <el-radio value="low">低</el-radio>
            <el-radio value="medium">中</el-radio>
            <el-radio value="high">高</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="探测引擎">
          <el-checkbox v-model="cfg.engines.sqlmap_enabled">SQLMap 初筛</el-checkbox>
          <el-checkbox v-model="cfg.engines.ai_probe_enabled">AI Payload 精细化</el-checkbox>
        </el-form-item>
        <div class="dim small">
          AI 接入（base_url / api_key / model）在「扫描配置」页设置；未配置时自动降级规则引擎。
        </div>
      </el-form>
      <template #footer>
        <el-button @click="dlg = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="create">创建并启动</el-button>
      </template>
    </el-dialog>

    <!-- 实时日志抽屉 -->
    <el-drawer v-model="drawer" :title="`实时日志 · 任务 #${activeTask?.id ?? ''}`" size="60%">
      <div class="drawer-toolbar">
        <el-tag :type="stream.connected.value ? 'success' : 'info'" size="small">
          {{ stream.connected.value ? '已连接' : '未连接' }}
        </el-tag>
        <el-button size="small" @click="stream.open(activeTask?.id)">重连</el-button>
        <el-button size="small" @click="stream.lines.value = []">清屏</el-button>
        <el-button size="small" type="danger" plain :loading="clearingLogs"
                   @click="clearServerLogs">清空日志</el-button>
        <span class="dim small">channel: task/collect/waf/ai/scan/vuln/system</span>
      </div>
      <div class="log-view" ref="logBox">
        <div v-for="(l, i) in stream.lines.value" :key="i" :class="'lv-' + (l.level || 'info')">
          <span class="dim">[{{ fmtTime(l.ts) }}][{{ l.channel }}]</span> {{ l.message }}
        </div>
        <div v-if="!stream.lines.value.length" class="dim">（暂无输出）</div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { reactive, ref, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'
import http from '../api/http'
import { useLogStream } from '../composables/logStream'

const router = useRouter()
const items = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 10
const loading = ref(false)
const statusFilter = ref('')
const STATUSES = ['created', 'collecting', 'scanning', 'review', 'done', 'stopped', 'error']

const dlg = ref(false)
const creating = ref(false)
const form = reactive({ name: '', target: '', collect_mode: 'both' })
const cfg = reactive({ intensity: 'medium', engines: { sqlmap_enabled: true, ai_probe_enabled: true } })

const drawer = ref(false)
const activeTask = ref(null)
const stream = useLogStream(800)
const logBox = ref(null)

function reload() { page.value = 1; load() }

async function load() {
  loading.value = true
  try {
    const params = { page: page.value, page_size: pageSize }
    if (statusFilter.value) params.status = statusFilter.value
    const { data } = await http.get('/task', { params })
    items.value = data.items
    total.value = data.total
  } finally { loading.value = false }
}

function openCreate() {
  form.name = ''; form.target = ''; form.collect_mode = 'both'
  cfg.intensity = 'medium'
  cfg.engines = { sqlmap_enabled: true, ai_probe_enabled: true }
  dlg.value = true
}

async function create() {
  if (!form.name || !form.target) { ElMessage.warning('请填写任务名与目标 URL'); return }
  creating.value = true
  try {
    const { data } = await http.post('/task', {
      name: form.name, target: form.target, collect_mode: form.collect_mode,
      scan_config: JSON.parse(JSON.stringify(cfg)),
    })
    const { data: started } = await http.post(`/task/${data.id}/start`)
    dlg.value = false
    ElMessage.success(`任务 #${started.id} 已创建并启动`)
    reload()
    openLogs(started)
  } catch { /* 拦截器已提示 */ } finally { creating.value = false }
}

async function start(row) {
  await http.post(`/task/${row.id}/start`)
  ElMessage.success(`任务 #${row.id} 已启动`)
  openLogs(row); load()
}

async function stop(row) {
  await http.post(`/task/${row.id}/stop`)
  ElMessage.warning(`任务 #${row.id} 已发出终止信号`)
  load()
}

const selected = ref([])
function onSelect(rows) { selected.value = rows }

async function del(row) {
  await ElMessageBox.confirm(
    `硬删除任务「${row.name}」及其采集/漏洞/证据？（不可恢复）`,
    '确认删除', { type: 'warning' },
  )
  await http.delete(`/task/${row.id}`)
  ElMessage.success('已硬删除'); load()
}

async function batchDel() {
  const ids = selected.value.map(r => r.id)
  if (!ids.length) return
  await ElMessageBox.confirm(
    `硬删除选中的 ${ids.length} 个任务及其全部关联数据？（不可恢复）`,
    '批量删除', { type: 'warning' },
  )
  const { data } = await http.post('/task/batch-delete', { ids })
  const skipN = (data.skipped || []).length
  ElMessage.success(`已删除 ${data.deleted?.length || 0} 个` + (skipN ? `，跳过运行中 ${skipN} 个` : ''))
  selected.value = []
  load()
}

function goReview(row) { router.push(`/collect/${row.id}?tab=review`) }
function goCollect(row) { router.push(`/collect/${row.id}`) }

async function openLogs(row) {
  activeTask.value = row
  drawer.value = true
  stream.open(row.id)
}

const clearingLogs = ref(false)
async function clearServerLogs() {
  clearingLogs.value = true
  try {
    const { data } = await http.post('/scan/logs/clear', { task_id: activeTask?.id ?? null })
    stream.lines.value = []          // 本地列表同步清空
    ElMessage.success(`已清空 ${data?.cleared ?? 0} 条日志`)
  } catch (e) {
    // 拦截器已提示错误
  } finally {
    clearingLogs.value = false
  }
}

const canStart = (r) => ['created', 'stopped', 'error'].includes(r.status)
const canStop = (r) => ['collecting', 'scanning'].includes(r.status)
const fmtTime = (iso) => {
  // 后端存 UTC ISO（带 Z）：必须真转本地时区（旧实现只替换字符串，UI 显 UTC 差 8 小时）
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const STATUS_LABEL = { created: '已创建', collecting: '采集中', scanning: '扫描中',
                       review: '待研判', done: '完成', stopped: '已终止', error: '异常' }
function statusLabel(s) { return STATUS_LABEL[s] || s }
function statusTag(s) {
  return { created: 'info', collecting: 'primary', scanning: 'warning',
           review: 'warning', done: 'success', stopped: 'info', error: 'danger' }[s] || 'info'
}

let timer = null
let scroller = null
onMounted(() => {
  load()
  // 有运行中任务时轮询刷新列表
  timer = setInterval(() => {
    if (items.value.some(r => ['collecting', 'scanning'].includes(r.status))) load()
  }, 8000)
  // 日志自动滚底
  scroller = setInterval(() => {
    const el = logBox.value
    if (el) el.scrollTop = el.scrollHeight
  }, 1500)
})
onBeforeUnmount(() => {
  clearInterval(timer)
  clearInterval(scroller)
  stream.close()
})
</script>

<style scoped>
.toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }
.toolbar .hint { color: var(--text-dim); font-size: 12px; }
.dim { color: var(--text-dim); }
.small { font-size: 12px; }
.mono { font-family: Consolas, monospace; }
.drawer-toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 10px; }
.log-view { height: calc(100vh - 170px); }
.lv-warn { color: #e6a23c; }
.lv-error { color: #f56c6c; }
.lv-success { color: #67c23a; }
</style>
