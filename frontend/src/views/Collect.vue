<template>
  <div class="page-wrap">
    <h2 class="page-title">接口采集</h2>

    <!-- 未选定任务：先点 URL / 任务，再看接口 -->
    <template v-if="!taskId">
      <el-card class="panel-card">
        <div class="toolbar" style="margin-bottom: 12px">
          <div class="burp-lamp">
            <span class="dot" :class="anyOnline ? 'on' : 'off'"></span>
            Burp 插件：{{ anyOnline ? '在线' : '离线' }}
          </div>
          <span class="dim small">点击下方任务目标 URL，进入该任务专属接口列表</span>
        </div>
        <el-empty v-if="!tasks.length" description="暂无任务，请先在任务面板创建" />
        <div v-else class="task-url-list">
          <div v-for="t in tasks" :key="t.id" class="task-url-card" @click="enterTask(t.id)">
            <div class="row1">
              <el-tag size="small" type="info">#{{ t.id }}</el-tag>
              <span class="name">{{ t.name }}</span>
              <el-tag size="small" :type="statusTag(t.status)">{{ statusLabel(t.status) }}</el-tag>
            </div>
            <div class="url mono" :title="t.target">{{ t.target }}</div>
            <div class="dim small">采集模式 {{ t.collect_mode }} · 点此查看该 URL 下接口</div>
          </div>
        </div>
      </el-card>
    </template>

    <!-- 已选定任务：接口列表 + AI 研判 Tab -->
    <template v-else>
      <el-card class="panel-card" style="margin-bottom: 14px">
        <div class="toolbar">
          <el-button text type="primary" @click="backToList">← 返回任务 URL 列表</el-button>
          <el-tag type="info">任务 #{{ taskId }}</el-tag>
          <span class="name">{{ currentTask?.name || '' }}</span>
          <el-tag size="small" :type="statusTag(currentTask?.status)">
            {{ statusLabel(currentTask?.status) }}
          </el-tag>
          <div class="burp-lamp" style="margin-left: auto">
            <span class="dot" :class="anyOnline ? 'on' : 'off'"></span>
            Burp {{ anyOnline ? '在线' : '离线' }}
          </div>
        </div>
        <div class="target-banner mono">
          目标基址：{{ currentTask?.target || '-' }}
        </div>
        <el-tabs v-model="mainTab" style="margin-top: 10px" @tab-change="onMainTab">
          <el-tab-pane label="接口列表" name="endpoints"></el-tab-pane>
          <el-tab-pane label="AI 研判" name="review"></el-tab-pane>
        </el-tabs>
      </el-card>

      <template v-if="mainTab === 'review'">
        <el-card class="panel-card">
          <AiReviewPanel :task-id="taskId" />
        </el-card>
      </template>

      <template v-else>
      <el-card class="panel-card" style="margin-bottom: 14px" v-if="chains.length">
        <template #header>业务链路（任务 #{{ taskId }}）</template>
        <div v-for="c in chains" :key="c.id" class="chain-row">
          <el-tag size="small" type="info">{{ c.reconstruct_method }}</el-tag>
          <span class="mono dim small">conf={{ c.confidence }}</span>
          <span class="chain-name">{{ c.name }}</span>
        </div>
      </el-card>

      <el-card class="panel-card">
        <div class="toolbar">
          <el-select v-model="q.read_write" placeholder="读写" clearable style="width: 120px"
                     @change="reload">
            <el-option label="读" value="read" /><el-option label="写" value="write" />
          </el-select>
          <el-select v-model="q.source" placeholder="来源" clearable style="width: 130px"
                     @change="reload">
            <el-option label="爬虫" value="crawler" />
            <el-option label="Burp" value="burp" />
            <el-option label="手动" value="manual" />
          </el-select>
          <el-input v-model="q.keyword" placeholder="路径关键字" clearable style="width: 200px"
                    @change="reload" />
          <el-button type="primary" @click="openManual">＋ 手动拼接录入</el-button>
          <span class="dim small">本任务共 {{ total }} 个接口</span>
        </div>

        <el-table :data="items" v-loading="loading" stripe>
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="任务" width="80">
            <template #default> #{{ taskId }} </template>
          </el-table-column>
          <el-table-column label="来源" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="sourceType(row.source)">{{ row.source }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="method" label="方法" width="70">
            <template #default="{ row }">
              <span :class="'m-' + row.method">{{ row.method }}</span>
            </template>
          </el-table-column>
          <el-table-column label="完整 URL（点击查看 AI 判断）" min-width="280">
            <template #default="{ row }">
              <el-link type="primary" class="ellipsis mono" :title="fullUrl(row)"
                       @click="openJudgment(row)">
                {{ fullUrl(row) }}
              </el-link>
            </template>
          </el-table-column>
          <el-table-column label="参数" min-width="160">
            <template #default="{ row }">
              <el-tooltip v-if="row.params && row.params.length" placement="top">
                <template #content>
                  <div v-for="p in row.params" :key="p.name">
                    {{ p.name }}（{{ p.location }}）{{ p.sample_value ? '=' + p.sample_value : '' }}
                  </div>
                </template>
                <span class="dim small">{{ row.params.map(p => p.name).join(', ') }}</span>
              </el-tooltip>
              <span v-else class="dim">-</span>
            </template>
          </el-table-column>
          <el-table-column label="读写" width="70">
            <template #default="{ row }">
              <el-tag size="small" :type="row.read_write === 'write' ? 'danger' : 'info'">
                {{ row.read_write === 'write' ? '写' : '读' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="235" fixed="right">
            <template #default="{ row }">
              <el-button size="small" text type="primary" @click="openJudgment(row)">判断</el-button>
              <el-button size="small" text type="success" :loading="scanningId === row.id"
                         @click="scanEndpoint(row)">扫描</el-button>
              <el-button size="small" text type="warning"
                         @click="addConfirmedPayload(row)">Payload</el-button>
              <el-button size="small" text type="danger" @click="removeEndpoint(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>

        <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
                       layout="total, prev, pager, next" @current-change="load" />
      </el-card>

      <!-- 点 URL → AI 是否存在 SQL 的判断 -->
      <el-drawer v-model="judgeDlg" size="560px" title="接口 AI 判断 · 是否存在 SQL 注入">
        <div v-if="judgeLoading" class="dim">加载中…</div>
        <template v-else-if="judgment">
          <div class="verdict-box" :class="'v-' + judgment.sql_verdict">
            <div class="v-icon">{{ verdictIcon(judgment.sql_verdict) }}</div>
            <div class="v-main">
              <div class="v-kicker">AI 研判结论</div>
              <div class="v-title">{{ judgment.sql_verdict_label }}</div>
              <div class="v-url mono">
                {{ judgment.endpoint.method }} {{ judgment.endpoint.host }}{{ judgment.endpoint.raw_path || judgment.endpoint.path }}
              </div>
              <div v-if="judgment.assessment" class="v-stats">
                <span>风险分 <b :style="{ color: scoreColor(judgment.assessment.risk_score) }">
                  {{ Math.round(judgment.assessment.risk_score) }}</b></span>
                <span>置信度 <b>{{ (judgment.assessment.confidence * 100).toFixed(0) }}%</b></span>
                <span>路由 <b>{{ routeLabel(judgment.assessment.route) }}</b></span>
              </div>
            </div>
          </div>

          <div v-if="probeAll404" class="result-note warn">
            该接口当前返回 404，全部探针无差异；请检查采集到的 URL / 表单 action 是否正确。
          </div>

          <h4 class="sec-title">研判理由</h4>
          <template v-if="judgment.assessment">
            <div class="meta-grid">
              <div class="meta-item"><span class="dim">引擎</span><b>{{ engineLabel(judgment.assessment.model_info) }}</b></div>
              <div class="meta-item"><span class="dim">Tokens</span><b class="mono">{{ judgment.assessment.model_info?.tokens ?? '-' }}</b></div>
              <div class="meta-item"><span class="dim">DBMS 推测</span><b>{{ judgment.assessment.model_info?.likely_dbms || '未知' }}</b></div>
              <div class="meta-item"><span class="dim">注入提示</span><b>{{ judgment.assessment.model_info?.injection_hint || '未知' }}</b></div>
            </div>
            <ol v-if="judgment.assessment.reasons?.length" class="thought-list">
              <li v-for="(r, i) in judgment.assessment.reasons" :key="i">{{ r }}</li>
            </ol>
            <div v-else class="dim">无详细理由</div>

            <template v-if="probeRows.length">
              <h4 class="sec-title">探针证据</h4>
              <div v-if="probeUniform" class="probe-summary">
                <el-tag size="small" :type="probeAll404 ? 'info' : 'warning'">
                  {{ probeAll404 ? '接口 404' : '全部无差异' }}
                </el-tag>
                <span>{{ probeSummaryText }}</span>
              </div>
              <el-collapse v-else class="probe-collapse">
                <el-collapse-item :title="`探针明细（${probeRows.length} 条，存在响应差异）`">
                  <div class="probe-list">
                    <div v-for="(p, i) in probeRows" :key="i" class="probe-row">
                      <span class="probe-label mono">{{ p.param || '-' }} · {{ p.label || '-' }}</span>
                      <el-tag size="small" :type="p.error ? 'danger' : p.sql_error_like ? 'warning' : 'info'">
                        {{ p.error ? '超时/错误' : (p.status || '-') }}
                      </el-tag>
                      <span class="dim small">长度 {{ p.length ?? '-' }}</span>
                      <span v-if="p.sql_error_like" class="probe-hit">SQL 报错特征</span>
                    </div>
                  </div>
                </el-collapse-item>
              </el-collapse>
            </template>
          </template>
          <el-empty v-else description="该接口尚未被 AI 研判（先启动任务跑完研判阶段）" :image-size="72" />

          <template v-if="jobRows.length">
            <h4 class="sec-title">探测记录</h4>
            <div class="job-summary">{{ jobSummary }}</div>
            <el-collapse class="job-collapse">
              <el-collapse-item :title="`查看探测记录（${jobRows.length} 条）`">
                <div class="job-list">
                  <div v-for="j in jobRows" :key="j.id" class="job-card">
                    <div class="job-top">
                      <el-tag size="small">{{ engineText(j.engine) }}</el-tag>
                      <span class="mono dim">#{{ j.id }}</span>
                      <el-tag size="small"
                              :type="j.result_class === 'vuln_confirmed' ? 'danger'
                                     : (j.engine === 'sqlmap_deep' && j.result_class === 'exploit_ok'
                                        ? 'success' : 'info')">
                        {{ jobResultLabel(j) }}
                      </el-tag>
                    </div>
                    <div class="dim small">{{ fmtTime(j.finished_at) || '未完成' }}</div>
                  </div>
                </div>
              </el-collapse-item>
            </el-collapse>
          </template>
          <div v-else class="empty-line">暂无探测记录</div>

          <template v-if="judgment.vulnerabilities?.length">
            <h4 class="sec-title">关联漏洞</h4>
            <div class="vuln-list">
              <div v-for="v in judgment.vulnerabilities" :key="v.id" class="vuln-card">
                <div class="vuln-top">
                  <el-tag size="small" type="danger">{{ vulnTypeLabel(v.vuln_type) }}</el-tag>
                  <span class="vuln-title">{{ v.title || v.severity }}</span>
                  <el-tag size="small" :type="v.status === 'confirmed' ? 'danger'
                                         : v.status === 'false_positive' ? 'info' : 'warning'">
                    {{ vulnStatusLabel(v.status) }}
                  </el-tag>
                </div>
                <div class="dim small">{{ v.dbms || '未知数据库' }}</div>
              </div>
              <div class="result-note">
                探测结果与 AI 研判结论可能不一致，以实际探测证据为准。
              </div>
            </div>
          </template>
        </template>
      </el-drawer>

      <el-dialog v-model="manualDlg" title="手动拼接录入接口" width="660">
        <el-alert type="info" :closable="false" style="margin-bottom: 12px"
                  :title="`基址：${currentTask?.target || ''}`" />
        <el-form :model="manual" label-width="96px">
          <el-form-item label="请求方法">
            <el-select v-model="manual.method" style="width: 140px">
              <el-option v-for="m in METHODS" :key="m" :label="m" :value="m" />
            </el-select>
          </el-form-item>
          <el-form-item label="路径">
            <el-input v-model="manual.path" placeholder="/check 或 /check?id=1" />
          </el-form-item>
          <el-form-item label="参数">
            <div class="param-list">
              <div v-for="(p, i) in manual.params" :key="i" class="param-row">
                <el-input v-model="p.name" placeholder="参数名" style="width: 140px" />
                <el-select v-model="p.location" style="width: 110px">
                  <el-option label="query" value="query" />
                  <el-option label="body" value="body" />
                  <el-option label="header" value="header" />
                </el-select>
                <el-input v-model="p.sample_value" placeholder="样例值" style="flex: 1" />
                <el-button text type="danger" @click="manual.params.splice(i, 1)">删</el-button>
              </div>
              <el-button size="small"
                         @click="manual.params.push({ name: '', location: 'query', sample_value: '' })">
                ＋ 参数
              </el-button>
            </div>
          </el-form-item>
          <el-form-item label="拼接预览">
            <code class="preview mono">{{ manual.method }} {{ previewUrl }}</code>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="manualDlg = false">取消</el-button>
          <el-button type="primary" :loading="manualSaving" @click="saveManual">保存到任务 #{{ taskId }}</el-button>
        </template>
      </el-dialog>
      </template><!-- /endpoints tab -->
    </template><!-- /task selected -->
  </div>
</template>

<script setup>
import { reactive, ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import http from '../api/http'
import AiReviewPanel from '../components/AiReviewPanel.vue'

const route = useRoute()
const router = useRouter()
const tasks = ref([])
const taskId = ref(null)
const mainTab = ref('endpoints')
const items = ref([])
const chains = ref([])
const burpItems = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 15
const loading = ref(false)
const q = reactive({ read_write: '', source: '', keyword: '' })
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const manualDlg = ref(false)
const manualSaving = ref(false)
const manual = reactive({
  method: 'GET',
  path: '/check',
  params: [{ name: 'id', location: 'query', sample_value: '1' }],
})
const judgeDlg = ref(false)
const judgeLoading = ref(false)
const judgment = ref(null)

function routeLabel(r) {
  return { auto_pass: '自动放行', manual_review: '待人工复核', suspicious: '存疑深测' }[r] || (r || '-')
}
function engineLabel(info) {
  if (!info) return '-'
  if (info.provider === 'rule-engine') return '规则引擎'
  return info.model || info.provider || 'AI'
}
function engineText(e) {
  return { sqlmap_deep: '深入利用', sqlmap: 'SQLMap 初筛', ai_probe: 'AI 探针' }[e] || e || '-'
}
function jobResultLabel(j) {
  if (!j) return '-'
  if (j.engine === 'sqlmap_deep') {
    if (j.result_class === 'exploit_ok') return '深挖完成'
    if (j.result_class === 'unreachable') return '目标不可达'
  }
  return resultLabel(j.result_class, j.status)
}
function fmtTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} `
       + `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
const RESULT_LABEL = {
  vuln_confirmed: '已确认漏洞', exploit_ok: '利用成功', no_vuln: '未发现',
  waf_blocked: '被拦截', inconclusive: '不确定', timeout: '超时',
  error: '错误', unreachable: '目标不可达', queued: '排队中',
  running: '运行中', finished: '已完成', killed: '已终止',
}
function resultLabel(r, fallback) { return RESULT_LABEL[r] || r || fallback || '-' }
const VULN_TYPE_LABEL = {
  sql_injection_boolean: 'SQL注入·布尔盲注',
  sql_injection_time: 'SQL注入·时间盲注',
  sql_injection_error: 'SQL注入·报错注入',
  sql_injection_union: 'SQL注入·UNION注入',
}
function vulnTypeLabel(t) { return VULN_TYPE_LABEL[t] || t || '-' }
const VULN_STATUS_LABEL = { pending_review: '待复核', confirmed: '已确认', false_positive: '误报' }
function vulnStatusLabel(s) { return VULN_STATUS_LABEL[s] || s || '-' }
function verdictIcon(v) {
  return { confirmed: '✓', detected: '✓', suspected: '!', not_found: '✓',
           low_risk: '✓', pending: '…' }[v] || '·'
}
function scoreColor(s) {
  if (s >= 70) return '#ff8aa8'
  if (s >= 40) return '#e8bb6b'
  return '#8fd46a'
}

const probeRows = computed(() => judgment.value?.assessment?.model_info?.probes || [])
const probeAll404 = computed(() => probeRows.value.length > 0
  && probeRows.value.every(p => p.status === 404))
const probeUniform = computed(() => {
  if (!probeRows.value.length) return false
  const sigs = new Set(probeRows.value.map(p =>
    `${p.status}|${p.length}|${p.sql_error_like ? 1 : 0}|${p.error ? 'e' : ''}`))
  return sigs.size === 1
})
const probeSummaryText = computed(() => {
  const ps = probeRows.value
  if (!ps.length) return ''
  const p = ps[0]
  const status = p.error ? '超时/错误' : (p.status || '-')
  return `全部 ${ps.length} 次探针均返回 ${status} / ${p.length ?? '-'} 字节，无任何差异`
})
const jobRows = computed(() => judgment.value?.scan_jobs || [])
const jobSummary = computed(() => {
  const counts = {}
  for (const j of jobRows.value) {
    const k = engineText(j.engine)
    counts[k] = (counts[k] || 0) + 1
  }
  return Object.entries(counts).map(([k, n]) => `${k} ${n} 次`).join(' · ')
})

async function openJudgment(row) {
  judgeDlg.value = true
  judgeLoading.value = true
  judgment.value = null
  try {
    const { data } = await http.get(`/ai/endpoint/${row.id}/judgment`)
    judgment.value = data
  } catch { /* interceptor */ } finally { judgeLoading.value = false }
}

const anyOnline = computed(() => burpItems.value.some(b => b.online))
const currentTask = computed(() => tasks.value.find(t => t.id === taskId.value) || null)

const STATUS_LABEL = { created: '已创建', pending: '已创建', collecting: '采集中', scanning: '扫描中',
                       review: '待研判', done: '完成', stopped: '已终止', terminated: '已终止', error: '异常' }
function statusLabel(s) { return STATUS_LABEL[s] || s || '-' }
function statusTag(s) {
  return { created: 'info', pending: 'info', collecting: 'primary', scanning: 'warning',
           review: 'warning', done: 'success', stopped: 'info', terminated: 'info', error: 'danger' }[s] || 'info'
}
function sourceType(s) {
  if (s === 'burp') return 'success'
  if (s === 'manual') return 'warning'
  return 'info'
}

function fullUrl(row) {
  const host = row.host || ''
  const path = row.raw_path || row.path || '/'
  const scheme = (currentTask.value?.target || 'http://').startsWith('https') ? 'https' : 'http'
  let url = `${scheme}://${host}${path.startsWith('/') ? path : '/' + path}`
  const qps = (row.params || []).filter(p => p.location === 'query')
  if (qps.length) {
    const qs = qps.map(p => `${encodeURIComponent(p.name)}=${encodeURIComponent(p.sample_value || '')}`).join('&')
    url += (url.includes('?') ? '&' : '?') + qs
  }
  return url
}

const previewUrl = computed(() => {
  const base = currentTask.value?.target || 'http://host/'
  let path = (manual.path || '/').trim() || '/'
  if (!path.startsWith('/') && !path.startsWith('http')) path = '/' + path
  let url
  try {
    url = path.startsWith('http') ? new URL(path) : new URL(path.replace(/^\//, ''), base.endsWith('/') ? base : base + '/')
  } catch {
    return '(路径不合法)'
  }
  for (const p of manual.params) {
    if (!p.name || p.location !== 'query') continue
    url.searchParams.set(p.name, p.sample_value || '')
  }
  return url.toString()
})

async function loadTasks() {
  const { data } = await http.get('/task', { params: { page: 1, page_size: 100 } })
  tasks.value = data.items
}

function enterTask(id) {
  router.push({ path: `/collect/${id}`, query: route.query.tab ? { tab: route.query.tab } : {} })
}

function backToList() {
  router.push('/collect')
}

function onMainTab(name) {
  router.replace({ path: `/collect/${taskId.value}`, query: name === 'review' ? { tab: 'review' } : {} })
}

function syncFromRoute() {
  const preset = Number(route.params.taskId)
  mainTab.value = route.query.tab === 'review' ? 'review' : 'endpoints'
  if (preset) {
    taskId.value = preset
    reload()
    loadChains()
  } else {
    taskId.value = null
    items.value = []
    chains.value = []
    total.value = 0
  }
}

function reload() { page.value = 1; load() }

async function load() {
  if (!taskId.value) return
  loading.value = true
  try {
    const params = { task_id: taskId.value, page: page.value, page_size: pageSize }
    if (q.read_write) params.read_write = q.read_write
    if (q.source) params.source = q.source
    if (q.keyword) params.keyword = q.keyword
    const { data } = await http.get('/collect/endpoints', { params })
    items.value = data.items
    total.value = data.total
  } finally { loading.value = false }
}

async function addConfirmedPayload(row) {
  let value
  try {
    ({ value } = await ElMessageBox.prompt(
      '粘贴手工验证成功的 payload（整段参数值，如 zhangsan\'and(1=1)and\'1\'=\'1）。' +
      '探测器会用它做受控对照复测，并优先提取 ~data~ 回显。',
      '确认 Payload 导入',
      { inputType: 'textarea', confirmButtonText: '保存', cancelButtonText: '取消' }))
  } catch { return }
  if (!value || !value.trim()) return
  try {
    const { data } = await http.post(`/collect/endpoints/${row.id}/confirmed-payload`,
                                     { payload: value.trim() })
    const ctx = data.context || {}
    ElMessage.success(`已保存到接口 #${row.id}：闭合符=${ctx.quote || '未知'}，前缀=${ctx.prefix || '-'}`)
    try {
      await ElMessageBox.confirm('是否立即用该 payload 定向重扫此接口？', '立即重扫',
                                 { type: 'info', confirmButtonText: '立即重扫', cancelButtonText: '稍后' })
      await scanEndpoint(row)
    } catch { /* 稍后 */ }
  } catch { /* interceptor */ }
}

const scanningId = ref(null)
async function scanEndpoint(row) {
  scanningId.value = row.id
  try {
    const { data } = await http.post(`/collect/endpoints/${row.id}/scan`)
    ElMessage.success(`已开始定向重扫接口 #${row.id}，可在「任务面板 → 日志」查看进度`)
  } catch { /* interceptor */ } finally {
    scanningId.value = null
  }
}

async function removeEndpoint(row) {
  try {
    await ElMessageBox.confirm(
      `删除接口 ${row.method} ${fullUrl(row)}？\n该接口下的扫描任务与漏洞记录会一并删除。`,
      '确认删除', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch { return }
  try {
    const { data } = await http.delete(`/collect/endpoints/${row.id}`)
    ElMessage.success(`已删除接口 #${row.id}`
      + (data.deleted_vulns ? `（同时清理 ${data.deleted_vulns} 条漏洞）` : ''))
    if (items.value.length === 1 && page.value > 1) page.value -= 1
    load()
  } catch { /* interceptor */ }
}

async function loadChains() {
  chains.value = []
  if (!taskId.value) return
  const { data } = await http.get('/collect/chains', { params: { task_id: taskId.value } })
  chains.value = data.items
}

async function loadBurp() {
  try {
    const { data } = await http.get('/burp/status')
    burpItems.value = data.items
  } catch { /* ignore */ }
}

function openManual() {
  if (!taskId.value) { ElMessage.warning('请先进入某个任务'); return }
  manual.method = 'GET'
  manual.path = '/check'
  manual.params = [{ name: 'id', location: 'query', sample_value: '1' }]
  manualDlg.value = true
}

async function saveManual() {
  if (!manual.path.trim()) { ElMessage.warning('请填写路径'); return }
  const params = manual.params.filter(p => p.name && p.name.trim())
  manualSaving.value = true
  try {
    const { data } = await http.post('/collect/endpoints', {
      task_id: taskId.value,
      method: manual.method,
      url: previewUrl.value.includes('(路径') ? manual.path.trim() : previewUrl.value,
      params,
    })
    ElMessage.success(`已录入到任务 #${taskId.value}：${data.item?.method} ${data.item?.raw_path || data.item?.path}`)
    manualDlg.value = false
    reload()
    // 录入只入库、不会自动扫描：给一次「立即定向重扫」的机会
    try {
      await ElMessageBox.confirm('接口已录入。是否立即对这个接口做一次定向重扫？',
                                 '立即扫描', { type: 'info',
                                               confirmButtonText: '立即扫描',
                                               cancelButtonText: '稍后' })
      if (data.item?.id) await scanEndpoint({ id: data.item.id })
    } catch { /* 稍后 */ }
  } catch { /* interceptor */ } finally { manualSaving.value = false }
}

watch(() => [route.params.taskId, route.query.tab], syncFromRoute)

let burpTimer = null
onMounted(async () => {
  await loadTasks()
  syncFromRoute()
  loadBurp()
  burpTimer = setInterval(loadBurp, 15000)
})
onBeforeUnmount(() => clearInterval(burpTimer))
</script>

<style scoped>
.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.dim { color: var(--text-dim); }
.small { font-size: 12px; }
.mono { font-family: Consolas, monospace; }
.name { color: var(--text-main); font-weight: 600; }
.burp-lamp { display: flex; align-items: center; gap: 6px; color: var(--text-main); }
.dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.dot.on { background: #67c23a; box-shadow: 0 0 6px #67c23a; }
.dot.off { background: #606266; }
.chain-row { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; }
.chain-name { color: var(--text-main); font-size: 13px; }
.m-GET { color: #67c23a; font-weight: 600; }
.m-POST { color: #e6a23c; font-weight: 600; }
.m-PUT, .m-DELETE { color: #f56c6c; font-weight: 600; }
.param-list { display: flex; flex-direction: column; gap: 8px; width: 100%; }
.param-row { display: flex; gap: 8px; align-items: center; width: 100%; }
.task-url-list { display: flex; flex-direction: column; gap: 10px; }
.task-url-card {
  border: 1px solid #30363d; border-radius: 8px; padding: 12px 14px; cursor: pointer;
  transition: border-color .15s, background .15s;
}
.task-url-card:hover { border-color: #58a6ff; background: #161b22; }
.task-url-card .row1 { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; }
.task-url-card .url { color: #58a6ff; font-size: 13px; word-break: break-all; }
.target-banner {
  margin-top: 8px; padding: 8px 10px; background: #0d1117; border-radius: 6px;
  color: #58a6ff; word-break: break-all;
}
.preview {
  display: block; width: 100%; padding: 8px 10px; background: #0d1117;
  border-radius: 6px; color: #7ee787; word-break: break-all; white-space: pre-wrap;
}
.verdict-box {
  display: flex; gap: 14px; padding: 16px;
  border-radius: 10px; margin-bottom: 16px;
  border: 1px solid var(--border-dim);
  background: linear-gradient(135deg, rgba(79, 140, 255, .06), transparent 60%);
}
.v-icon {
  flex: none; width: 36px; height: 36px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 18px; font-weight: 800;
  border: 1px solid currentColor;
  background: rgba(255, 255, 255, .04);
}
.v-main { min-width: 0; }
.v-kicker {
  font-size: 10.5px; letter-spacing: .6px;
  color: var(--text-dim); text-transform: uppercase;
}
.v-title { font-size: 17px; font-weight: 700; margin-top: 2px; color: var(--text-main); }
.v-url { margin-top: 4px; font-size: 12px; color: #c9d1d9; word-break: break-all; }
.v-stats {
  display: flex; gap: 14px; flex-wrap: wrap;
  margin-top: 10px; font-size: 12px; color: var(--text-dim);
}
.v-stats b { color: var(--text-main); font-weight: 600; }
.v-confirmed, .v-detected {
  color: #ff9ab5; border-color: rgba(255, 107, 138, .45);
  background: rgba(255, 107, 138, .07);
}
.v-suspected {
  color: #e8bb6b; border-color: rgba(230, 162, 60, .45);
  background: rgba(230, 162, 60, .07);
}
.v-not_found, .v-low_risk {
  color: #8fd46a; border-color: rgba(103, 194, 58, .4);
  background: rgba(103, 194, 58, .06);
}
.v-pending { color: #aab4bf; }

.sec-title {
  position: relative; padding-left: 10px;
  margin: 18px 0 10px; color: var(--text-main); font-size: 14px;
}
.sec-title::before {
  content: ""; position: absolute; left: 0; top: 50%;
  width: 3px; height: 12px; margin-top: -6px;
  border-radius: 2px; background: var(--grad);
}

.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 12px; margin-bottom: 12px; }
.meta-item {
  display: flex; flex-direction: column; gap: 3px;
  padding: 9px 11px; background: #0f141a;
  border: 1px solid var(--border-dim); border-radius: 8px;
}
.meta-item b { color: var(--text-main); font-weight: 600; font-size: 13px; }

.thought-list {
  margin: 0; padding: 12px 14px 12px 30px;
  color: #c9d1d9; line-height: 1.75;
  background: #0f141a; border: 1px solid var(--border-dim); border-radius: 8px;
}
.thought-list li { margin-bottom: 6px; }
.thought-list li::marker { color: var(--brand); }

.probe-list { display: flex; flex-direction: column; gap: 6px; }
.probe-row {
  display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  padding: 8px 10px; background: #0f141a;
  border: 1px solid var(--border-dim); border-radius: 7px;
}
.probe-label { color: var(--text-main); font-size: 12.5px; }
.probe-hit { color: #e8bb6b; font-size: 11.5px; }

.job-list, .vuln-list { display: flex; flex-direction: column; gap: 8px; }
.job-card, .vuln-card {
  padding: 10px 12px; background: #0f141a;
  border: 1px solid var(--border-dim); border-radius: 8px;
}
.job-top, .vuln-top {
  display: flex; gap: 8px; align-items: center;
  flex-wrap: wrap; margin-bottom: 4px;
}
.vuln-title { color: var(--text-main); font-size: 13px; }
.empty-line { color: var(--text-dim); font-size: 12.5px; padding: 8px 0; }
.result-note {
  margin-top: 8px; padding: 8px 10px; font-size: 12px;
  color: #9da7b3; background: rgba(79, 140, 255, .06);
  border-left: 2px solid rgba(79, 140, 255, .35); border-radius: 6px;
}
.result-note.warn {
  color: #e8bb6b;
  background: rgba(230, 162, 60, .08);
  border-left-color: rgba(230, 162, 60, .55);
}
.probe-summary, .job-summary {
  display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  padding: 10px 12px; background: #0f141a;
  border: 1px solid var(--border-dim); border-radius: 8px;
  color: var(--text-dim); font-size: 12.5px;
}
.probe-collapse, .job-collapse { margin-top: 4px; }
.dim { color: #9da7b3; }
</style>
