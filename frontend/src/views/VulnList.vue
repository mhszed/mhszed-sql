<template>
  <div class="page-wrap">
    <h2 class="page-title">漏洞结果</h2>

    <!-- 未选任务：像任务面板一样先列任务 URL -->
    <template v-if="!taskId">
      <el-card class="panel-card">
        <div class="toolbar">
          <span class="hint">点击任务目标 URL，查看该任务下的漏洞（与任务面板同一套归属）</span>
        </div>
        <el-empty v-if="!tasks.length" description="暂无任务" />
        <div v-else class="task-url-list">
          <div v-for="t in tasks" :key="t.id" class="task-url-card" @click="enterTask(t.id)">
            <div class="row1">
              <el-tag size="small" type="info">#{{ t.id }}</el-tag>
              <span class="name">{{ t.name }}</span>
              <el-tag size="small" :type="taskStatusTag(t.status)">{{ statusLabel(t.status) }}</el-tag>
            </div>
            <div class="url mono" :title="t.target">{{ t.target }}</div>
            <div class="dim small">
              点此查看该 URL / 任务的漏洞结果
              <el-tag v-if="(vulnCountMap[t.id] || 0) > 0" size="small" type="danger" style="margin-left: 8px">
                {{ vulnCountMap[t.id] }} 个漏洞
              </el-tag>
              <span v-else class="dim"> · 暂无漏洞</span>
            </div>
          </div>
        </div>
      </el-card>
    </template>

    <!-- 已选任务：只展示该任务漏洞，布局贴近任务面板 -->
    <template v-else>
      <el-card class="panel-card">
        <div class="toolbar">
          <el-button text type="primary" @click="backToList">← 返回任务列表</el-button>
          <el-tag type="info">任务 #{{ taskId }}</el-tag>
          <span class="name">{{ currentTask?.name }}</span>
          <el-tag size="small" :type="taskStatusTag(currentTask?.status)">
            {{ statusLabel(currentTask?.status) }}
          </el-tag>
          <el-select v-model="statusFilter" placeholder="状态" clearable style="width: 140px"
                     @change="reload">
            <el-option label="待复核" value="pending_review" />
            <el-option label="已确认" value="confirmed" />
            <el-option label="误报" value="false_positive" />
          </el-select>
          <el-button :loading="downloading" @click="downloadReport">导出加固报告</el-button>
          <span class="hint">本页只显示任务 #{{ taskId }} 的漏洞</span>
        </div>
        <div class="target-banner mono">目标：{{ currentTask?.target || '-' }}</div>

        <!-- 只有确认存在 WAF 才显示；没有 WAF 不占位 -->
        <div v-if="wafProfile && wafProfile.has_waf" class="waf-box">
          <span class="dim small">WAF 画像：</span>
          <el-tag size="small" type="danger">{{ wafProfile.product }}</el-tag>
          <span class="dim small">置信 {{ wafProfile.product_confidence }}</span>
          <span v-if="wafProfile.block_behavior" class="dim small">
            · 拦截行为：{{ wafProfile.block_behavior }}
          </span>
          <span v-if="wafBypass" class="dim small">· 建议绕过：{{ wafBypass }}</span>
        </div>

        <el-table :data="items" v-loading="loading" stripe style="margin-top: 12px">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="漏洞名" min-width="200">
            <template #default="{ row }">
              <el-link type="primary" @click="openDetail(row)">{{ row.title || typeLabel(row.vuln_type) }}</el-link>
            </template>
          </el-table-column>
          <el-table-column label="位置" min-width="200">
            <template #default="{ row }">
              <span class="ellipsis" :title="`${row.method} ${row.host || ''}${row.path}`">
                <span :class="'m-' + row.method">{{ row.method }}</span>
                {{ row.path }}
              </span>
            </template>
          </el-table-column>
          <el-table-column label="严重度" width="90">
            <template #default="{ row }">
              <el-tag :type="sevTag(row.severity)" size="small">{{ sevLabel(row.severity) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="DBMS" width="140">
            <template #default="{ row }">
              <span class="mono small">{{ row.dbms || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="vstTag(row.status)" size="small">{{ vstLabel(row.status) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="发现时间" width="160">
            <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="300" fixed="right">
            <template #default="{ row }">
              <el-button size="small" @click="openDetail(row)">证据链</el-button>
              <el-button size="small" type="warning"
                         v-if="row.status === 'pending_review' || row.status === 'confirmed'"
                         :loading="deepLoadingId === row.id"
                         @click="openDeep(row)">深入利用</el-button>
              <el-button size="small" type="primary" v-if="row.status === 'pending_review'"
                         @click="reviewVuln(row, 'confirm')">确认</el-button>
              <el-button size="small" type="danger" plain v-if="row.status === 'pending_review'"
                         @click="reviewVuln(row, 'false_positive')">误报</el-button>
            </template>
          </el-table-column>
        </el-table>

        <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
                       layout="total, prev, pager, next" @current-change="load"
                       style="margin-top: 12px" />
      </el-card>
    </template>

    <!-- 证据链：关键结论置顶 -->
    <el-drawer v-model="drawer" :title="`证据链 · 漏洞 #${activeVuln?.id ?? ''}`" size="60%">
      <div v-if="activeVuln" class="vuln-head">
        <div class="vh-top">
          <h3>{{ activeVuln.title }}</h3>
          <div class="vh-tags">
            <el-tag size="small" :type="sevTag(activeVuln.severity)">{{ sevLabel(activeVuln.severity) }}</el-tag>
            <el-tag size="small" :type="vstTag(activeVuln.status)">{{ vstLabel(activeVuln.status) }}</el-tag>
          </div>
        </div>
        <div class="key-facts">
          <div class="kf-item"><span class="dim">接口</span>
            <div class="mono ellipsis" :title="`${activeVuln.endpoint?.method} ${activeVuln.endpoint?.host}${activeVuln.endpoint?.path}`">
              {{ activeVuln.endpoint?.method }} {{ activeVuln.endpoint?.host }}{{ activeVuln.endpoint?.path }}
            </div>
          </div>
          <div class="kf-item"><span class="dim">数据库类型</span>
            <div class="mono">{{ activeVuln.dbms || '未知' }}</div>
          </div>
        </div>
        <div v-if="payloadEvidence" class="payload-box">
          <div class="dim small">确认 Payload</div>
          <pre class="mono">{{ payloadEvidence }}</pre>
        </div>
        <div v-if="deepSummary" class="deep-box">
          <div class="dim small">深入利用结果（证据链摘要）</div>
          <pre class="mono">{{ deepSummary }}</pre>
        </div>
      </div>
      <div class="ev-sec-title">关键证据</div>
      <el-timeline style="margin-top: 10px">
        <el-timeline-item v-for="ev in keyEvidence" :key="ev.seq"
                          :timestamp="fmtTime(ev.created_at)"
                          :type="evType(ev.evidence_type)" placement="top">
          <div class="ev-card">
            <div class="ev-head">
              <el-tag size="small" :type="evType(ev.evidence_type)">{{ evLabel(ev.evidence_type) }}</el-tag>
              <span v-if="ev.meta?.stage" class="ev-stage mono">stage={{ ev.meta.stage }}</span>
            </div>
            <pre class="ev-content mono">{{ ev.content }}</pre>
            <div class="ev-foot dim small">sha256: {{ ev.sha256?.slice(0, 16) }}…</div>
          </div>
        </el-timeline-item>
      </el-timeline>

      <el-collapse v-if="processEvidence.length" class="process-collapse">
        <el-collapse-item :title="`过程记录（${processEvidence.length} 条）`">
          <el-timeline>
            <el-timeline-item v-for="ev in processEvidence" :key="ev.seq"
                              :timestamp="fmtTime(ev.created_at)"
                              :type="evType(ev.evidence_type)" placement="top">
              <div class="ev-card">
                <div class="ev-head">
                  <el-tag size="small" :type="evType(ev.evidence_type)">{{ evLabel(ev.evidence_type) }}</el-tag>
                  <span v-if="ev.meta?.stage" class="ev-stage mono">stage={{ ev.meta.stage }}</span>
                </div>
                <pre class="ev-content mono">{{ ev.content }}</pre>
                <div class="ev-foot dim small">sha256: {{ ev.sha256?.slice(0, 16) }}…</div>
              </div>
            </el-timeline-item>
          </el-timeline>
        </el-collapse-item>
      </el-collapse>
      <div v-if="activeVuln?.hardening_advice?.length" class="advice">
        <h4>加固建议</h4>
        <ul>
          <li v-for="(a, i) in activeVuln.hardening_advice" :key="i">{{ a }}</li>
        </ul>
      </div>
    </el-drawer>

    <el-dialog v-model="deepDlg" title="深入利用" width="520">
      <p class="dim">针对已发现的 SQL 注入，用 sqlmap（可由 DeepSeek 规划）继续利用；失败时布尔盲注自抽兜底。</p>
      <div class="dim" style="margin: 6px 0">利用目标（每次必选）</div>
      <el-radio-group v-model="deepGoal" class="deep-modes">
        <el-radio value="schema" border>实战：库表 / 结构</el-radio>
        <el-radio value="flag" border>靶场：flag</el-radio>
      </el-radio-group>
      <div class="dim" style="margin: 12px 0 6px">利用方式</div>
      <el-radio-group v-model="deepMode" class="deep-modes">
        <el-radio value="ai" border>AI 自测（字符UNION / 布尔盲注，不依赖 sqlmap）</el-radio>
        <el-radio value="enum" border>sqlmap 枚举库表（失败再 AI 兜底）</el-radio>
        <el-radio value="dump" border>脱裤样本（最多 5 行，需二次确认）</el-radio>
      </el-radio-group>
      <div v-if="deepStatus" class="deep-status">
        <el-tag :type="deepStatus.status === 'error' ? 'danger' : deepStatus.status === 'done' ? 'success' : 'warning'" size="small">
          {{ deepStatus.status }}
        </el-tag>
        <span class="mono small">{{ deepStatus.stage }}</span>
        <div class="dim small" style="margin-top: 6px">{{ deepStatus.summary }}</div>
        <div v-if="deepResultRows.length" class="deep-result">
          <div class="dim small">已获取结果</div>
          <div v-for="r in deepResultRows" :key="r.label" class="deep-result-row">
            <span class="dim">{{ r.label }}</span>
            <span class="mono">{{ r.value }}</span>
          </div>
        </div>
        <div v-else-if="deepStatus.status !== 'idle'" class="dim small" style="margin-top: 8px">
          尚未取得数据库名 / 表 / 数据样本
        </div>
        <el-collapse v-if="deepStatus.logs?.length" class="deep-collapse">
          <el-collapse-item :title="`详细日志（${deepStatus.logs.length}）`">
            <div class="log-view deep-log">
              <div v-for="(l, i) in deepStatus.logs" :key="i">{{ l }}</div>
            </div>
          </el-collapse-item>
        </el-collapse>
      </div>
      <template #footer>
        <el-button @click="deepDlg = false">关闭</el-button>
        <el-button type="primary" :loading="deepStarting" :disabled="!deepGoal" @click="startDeep">开始</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import http from '../api/http'

const route = useRoute()
const router = useRouter()
const tasks = ref([])
const vulnCountMap = ref({})
const taskId = ref(null)
const items = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 10
const loading = ref(false)
const statusFilter = ref('')
const wafProfile = ref(null)
const wafBypass = computed(() => {
  const b = wafProfile.value?.bypass_suggestions
  return Array.isArray(b) ? b.join(' / ') : (b || '')
})

const drawer = ref(false)
const activeVuln = ref(null)
const evidence = ref([])
const downloading = ref(false)

const deepDlg = ref(false)
const deepMode = ref('ai')
const deepGoal = ref('')
const deepRow = ref(null)
const deepStarting = ref(false)
const deepLoadingId = ref(null)
const deepStatus = ref(null)
let deepTimer = null

const currentTask = computed(() => tasks.value.find(t => t.id === taskId.value) || null)
const payloadEvidence = computed(() => {
  const rows = (evidence.value || []).filter(e => e.evidence_type === 'payload')
  if (!rows.length) return ''
  const score = (ev) => {
    const c = ev.content || ''
    let s = c.length
    if (c.includes('/**/')) s += 10000
    if (/uunionnion/i.test(c) && /sselectelect/i.test(c)) s += 6000
    else if (/uunionnion|sselectelect/i.test(c)) s += 3000
    if (/sqlite_master/i.test(c)) s -= 4000
    return s
  }
  return [...rows].sort((a, b) => score(b) - score(a))[0].content || ''
})
const deepSummary = computed(() => {
  const rows = (evidence.value || []).filter(e => e.evidence_type === 'deep_exploit')
  if (!rows.length) return ''
  // 优先展示带真实成果的条目，避免被 “AI 0 命中” 之类的过程日志盖住
  const score = (ev) => {
    const c = ev.content || ''
    const m = ev.meta || {}
    let s = 0
    if (m.flag_sample || /flag\{/i.test(c)) s += 100
    if (m.tables || m.dbs || m.db_name || m.database) s += 50
    if (String(m.stage || '').startsWith('impact_')) s += 30
    if (/【深入利用结果|目标不可达/.test(c)) s += 20
    return s
  }
  // 同分时取最新一条，避免旧的 challdnges 之类错误结果压过修复后的 challenges
  const sorted = [...rows].sort((a, b) =>
    (score(b) - score(a)) || ((b.seq || 0) - (a.seq || 0)))
  // 只有这些阶段产出的表/库可信。union_extract 现在只对 SQLite 启用
  // （union_extract_allowed），且错误信封已被过滤，表名可信。
  const TRUSTED_TABLE = new Set(['impact_tables', 'dump_result',
    'union_extract', 'stop'])
  const TABLE_NOISE = new Set(['mysql_fetch_array', 'phpstudy', 'expects',
    'warning', 'notice', 'deprecated', 'fatal', 'parse', 'uncaught',
    'undefined', 'stack', 'trace', 'php', 'www', 'sqli', 'labs', 'dhakkan'])
  const cleanTables = (arr) => {
    const vals = (arr || []).map(x => String(x).trim()).filter(Boolean)
    return vals.some(v => TABLE_NOISE.has(v.toLowerCase())) ? [] : vals
  }
  const TRUSTED_SCHEMA = new Set(['impact_current_db', 'impact_db_name', 'current_db',
                                  'db_name', 'stop', 'result', 'blind_extract',
                                  'reuse', 'budget', 'unreachable'])
  let dbms = '', dbName = '', schema = '', sample = '', tables = [], extract = ''
  for (const ev of sorted) {
    const m = ev.meta || {}
    const c = ev.content || ''
    const stage = String(m.stage || '')
    if (!dbms) dbms = m.dbms || ''
    if (!dbName && stage !== '' && ['impact_db_name', 'db_name', 'stop', 'result']
      .includes(stage)) dbName = m.db_name || ''
    if (!schema && TRUSTED_SCHEMA.has(stage)) {
      schema = m.schema || (Array.isArray(m.dbs) ? (m.dbs[0] || '') : '') ||
               m.db || m.database || ''
    }
    if (!tables.length && TRUSTED_TABLE.has(stage) && Array.isArray(m.tables)) {
      tables = cleanTables(m.tables)
    }
    if (!sample) sample = m.flag_sample || ''
    if (!schema && TRUSTED_SCHEMA.has(stage)) {
      const mm = c.match(/current database[^:\n]*:\s*'?([\w\-.$]+)'?/i)
      if (mm) schema = mm[1]
    }
    if (!tables.length && TRUSTED_TABLE.has(stage)) {
      const mm = c.match(/(?:tables|表)\s*[:=]\s*\[([^\]]*)\]/i)
      if (mm) tables = cleanTables(mm[1].split(',').map(x => x.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean))
    }
    // 旧证据没有 extract_query：按阶段反推等价语句，保证界面能说明“怎么拿到的”
    if (!extract) {
      if (stage === 'impact_current_db') {
        extract = /postgres/i.test(m.dbms || '') ? 'SELECT current_schema()' : 'SELECT DATABASE()'
      } else if (stage === 'impact_db_name') {
        extract = 'SELECT current_database()'
      } else if (stage === 'impact_tables' && schema) {
        extract = `SELECT table_name FROM information_schema.tables WHERE table_schema='${schema}'`
      }
    }
    if (!sample) {
      const mm = c.match(/flag\{[^}]+\}/i)
      if (mm) sample = mm[0]
    }
  }
  // 提取方式两段式：sqlmap 实际参数优先，其次显式 query，最后才按阶段反推
  if (!extract) {
    for (const ev of sorted) {
      const ex = (ev.meta || {}).extract_extra || (ev.meta || {}).extra
      if (Array.isArray(ex) && ex.length) { extract = 'sqlmap ' + ex.join(' '); break }
    }
  }
  if (!extract) {
    for (const ev of sorted) {
      const q = (ev.meta || {}).extract_query
      if (q) { extract = String(q); break }
    }
  }
  if (!extract) {
    for (const ev of sorted) {
      const m = ev.meta || {}
      const stage = String(m.stage || '')
      if (stage === 'impact_current_db') {
        extract = /postgres/i.test(m.dbms || '') ? 'SELECT current_schema()' : 'SELECT DATABASE()'
        break
      }
      if (stage === 'impact_db_name') { extract = 'SELECT current_database()'; break }
      if (stage === 'impact_tables' && schema) {
        extract = `SELECT table_name FROM information_schema.tables WHERE table_schema='${schema}'`
        break
      }
    }
  }
  if (!dbms) dbms = activeVuln.value?.dbms || ''
  const payload = (payloadEvidence.value || '').split('\n')[0]
    .replace(/^\[[^\]]*\]\s*/, '').trim()
  const lines = []
  if (dbms) lines.push(`数据库类型：${dbms}`)
  if (payload) lines.push(`确认 Payload：${payload}`)
  if (dbName) lines.push(`数据库名：${dbName}`)
  if (schema && schema !== dbName) lines.push(`当前库/Schema：${schema}`)
  if (extract) {
    lines.push(extract.startsWith('sqlmap ') ? `sqlmap 提取命令：${extract}` : `提取语句：${extract}`)
  }
  if (tables.length) lines.push(`表：${tables.join(', ')}`)
  if (sample) lines.push(`数据样本/flag：${sample}`)
  if (!lines.length) lines.push('尚未取得数据库名 / 表 / 数据样本')
  return lines.join('\n')
})

const KEY_EVIDENCE_TYPES = new Set(['payload', 'request', 'waf_info',
  'chain_info', 'response', 'console_log'])
const KEY_DEEP_STAGES = new Set(['impact_current_db', 'impact_db_name',
  'impact_tables', 'impact_dbms', 'stop', 'result', 'dump_result',
  'blind_extract'])

const keyEvidence = computed(() => {
  const latest = new Map()
  for (const ev of evidence.value || []) {
    let key = ev.evidence_type
    if (ev.evidence_type === 'deep_exploit') {
      const stage = ev.meta?.stage
      if (!KEY_DEEP_STAGES.has(stage)) continue
      key = 'deep:' + stage
    } else if (!KEY_EVIDENCE_TYPES.has(ev.evidence_type)) {
      continue
    }
    latest.set(key, ev)   // 同一类型/阶段只保留最新一条，避免多次重跑刷屏
  }
  return Array.from(latest.values()).sort((a, b) => a.seq - b.seq)
})
const processEvidence = computed(() => {
  const keySeqs = new Set(keyEvidence.value.map(e => e.seq))
  return (evidence.value || []).filter(e => !keySeqs.has(e.seq))
})

const deepResultRows = computed(() => {
  const r = deepStatus.value?.result || {}
  const rows = []
  if (r.db_name) rows.push({ label: '数据库', value: r.db_name })
  if (r.schema && r.schema !== r.db_name) rows.push({ label: '当前库/Schema', value: r.schema })
  if (!r.db_name && !r.schema && r.dbs?.length) {
    rows.push({ label: '库/schema', value: r.dbs.join(', ') })
  }
  if (r.extract?.command) {
    const isSqlmap = String(r.extract.command).startsWith('sqlmap ')
    rows.push({ label: isSqlmap ? 'sqlmap 语句' : '提取语句', value: r.extract.command })
  } else if (r.extract?.query) {
    rows.push({ label: '提取语句', value: r.extract.query })
  }
  const _tableVals = (r.tables || []).map(t => String(t).trim()).filter(Boolean)
  const _noise = ['mysql_fetch_array', 'phpstudy', 'expects', 'warning', 'notice',
    'deprecated', 'fatal', 'parse', 'uncaught', 'undefined', 'stack',
    'trace', 'php', 'www', 'sqli', 'labs', 'dhakkan']
  const _tables = _tableVals.some(t => _noise.includes(t.toLowerCase())) ? [] : _tableVals
  if (_tables.length) rows.push({ label: '表', value: _tables.join(', ') })
  if (r.sample) rows.push({ label: '数据样本/flag', value: r.sample })
  return rows
})

const STATUS_LABEL = {
  created: '已创建', pending: '已创建', collecting: '采集中', scanning: '扫描中',
  review: '待研判', done: '完成', stopped: '已终止', terminated: '已终止', error: '异常',
}
function statusLabel(s) { return STATUS_LABEL[s] || s || '-' }
function taskStatusTag(s) {
  return { created: 'info', pending: 'info', collecting: 'primary', scanning: 'warning',
           review: 'warning', done: 'success', stopped: 'info', terminated: 'info', error: 'danger' }[s] || 'info'
}

function enterTask(id) { router.push(`/vulns/${id}`) }
function backToList() { router.push('/vulns') }

function syncFromRoute() {
  const preset = Number(route.params.taskId)
  if (preset) {
    taskId.value = preset
    reload()
    loadWaf()
  } else {
    taskId.value = null
    wafProfile.value = null
    items.value = []
    total.value = 0
  }
}

function reload() { page.value = 1; load() }

async function loadWaf() {
  if (!taskId.value) { wafProfile.value = null; return }
  try {
    const { data } = await http.get('/waf/profile', { params: { task_id: taskId.value } })
    wafProfile.value = data
  } catch {
    // 没有画像（404）或接口异常：安静地不显示，不影响漏洞列表
    wafProfile.value = null
  }
}

async function load() {
  if (!taskId.value) return
  loading.value = true
  try {
    const params = { task_id: taskId.value, page: page.value, page_size: pageSize }
    if (statusFilter.value) params.status = statusFilter.value
    const { data } = await http.get('/vuln', { params })
    items.value = data.items
    total.value = data.total
  } finally { loading.value = false }
}

async function openDetail(row) {
  const [{ data: v }, { data: ev }] = await Promise.all([
    http.get(`/vuln/${row.id}`),
    http.get(`/vuln/${row.id}/evidence`),
  ])
  activeVuln.value = v
  evidence.value = ev.items
  drawer.value = true
}

async function reviewVuln(row, action) {
  if (action === 'false_positive') {
    await ElMessageBox.confirm('标记为误报？将回流负样本库压制后续同类研判。', '漏洞复核', { type: 'info' })
    await http.post(`/vuln/${row.id}/review`, { action })
    ElMessage.success('已标记误报')
    load()
    return
  }
  // 确认：默认不回流；二次询问是否回流 Payload
  await ElMessageBox.confirm('确认为真实漏洞？', '漏洞复核', { type: 'warning' })
  let feedKb = false
  try {
    await ElMessageBox.confirm(
      '要把成功 Payload 回流到知识库吗？（可不回流，仅确认漏洞）',
      '回流知识库（可选）',
      { type: 'info', confirmButtonText: '回流', cancelButtonText: '不回流' },
    )
    feedKb = true
  } catch {
    feedKb = false
  }
  await http.post(`/vuln/${row.id}/review`, { action: 'confirm', feed_kb: feedKb })
  ElMessage.success(feedKb ? '已确认，并回流 Payload' : '已确认漏洞（未回流知识库）')
  load()
}

function openDeep(row) {
  deepRow.value = row
  deepMode.value = 'ai'
  deepGoal.value = ''
  deepStatus.value = null
  deepDlg.value = true
  pollDeepOnce(row.id)
}

async function startDeep() {
  if (!deepRow.value) return
  if (!deepGoal.value) {
    ElMessage.warning('请先选择利用目标（每次必选）')
    return
  }
  if (deepMode.value === 'dump') {
    await ElMessageBox.confirm(
      '将用 sqlmap 拉取至多 5 行样本，禁止全量脱库。确认继续？',
      '脱裤二次确认', { type: 'warning' },
    )
  }
  deepStarting.value = true
  deepLoadingId.value = deepRow.value.id
  try {
    const { data } = await http.post(`/vuln/${deepRow.value.id}/deep-exploit`, {
      mode: deepMode.value,
      goal: deepGoal.value,
    })
    deepStatus.value = data.status
    ElMessage.success(
      deepMode.value === 'ai' ? '已开始 AI 自测'
        : deepMode.value === 'enum' ? '已开始 sqlmap 枚举' : '已开始受限脱裤',
    )
    startDeepPoll(deepRow.value.id)
  } catch { /* interceptor */ } finally { deepStarting.value = false }
}

async function pollDeepOnce(id) {
  try {
    const { data } = await http.get(`/vuln/${id}/deep-exploit/status`)
    deepStatus.value = data
    return data
  } catch { return null }
}

function startDeepPoll(id) {
  stopDeepPoll()
  deepTimer = setInterval(async () => {
    const st = await pollDeepOnce(id)
    if (st && ['done', 'error', 'idle'].includes(st.status)) {
      stopDeepPoll()
      deepLoadingId.value = null
      if (st.status === 'done') ElMessage.success(st.summary || '深入利用完成，可在证据链查看')
      if (st.status === 'error') ElMessage.error(st.summary || '深入利用失败')
    }
  }, 3000)
}

function stopDeepPoll() {
  if (deepTimer) { clearInterval(deepTimer); deepTimer = null }
}

async function downloadReport() {
  downloading.value = true
  try {
    const resp = await http.get('/vuln/report/download', {
      params: { task_id: taskId.value },
      responseType: 'blob',
    })
    const blob = new Blob([resp.data])
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report_task_${taskId.value}.pdf`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('报告已生成并下载')
  } finally { downloading.value = false }
}

const TYPE_LABEL = { sql_injection_boolean: 'SQL注入·布尔盲注', sql_injection_time: 'SQL注入·时间盲注',
                     sql_injection_error: 'SQL注入·报错', sql_injection_union: 'SQL注入·UNION' }
function typeLabel(t) { return TYPE_LABEL[t] || t }
function sevLabel(s) { return { critical: '严重', high: '高危', medium: '中危', low: '低危' }[s] || s }
function sevTag(s) { return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || 'info' }
function vstLabel(s) { return { pending_review: '待复核', confirmed: '已确认', false_positive: '误报' }[s] || s }
function vstTag(s) { return { pending_review: 'warning', confirmed: 'danger', false_positive: 'info' }[s] || 'info' }
function evType(t) { return { payload: 'danger', request: 'primary', waf_info: 'warning',
                             chain_info: 'info', console_log: 'info', response: 'success',
                             deep_exploit: 'warning' }[t] || 'info' }
function evLabel(t) {
  return {
    payload: '确认 Payload', request: '请求特征', waf_info: 'WAF 画像',
    chain_info: '业务链路', console_log: 'sqlmap 输出', response: '响应样本',
    deep_exploit: '深入利用',
  }[t] || t
}
function fmtTime(iso) {
  // 后端存 UTC ISO（带 Z）：必须真转本地时区（旧实现只替换字符串，UI 显 UTC 差 8 小时）
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

watch(() => route.params.taskId, syncFromRoute)

async function loadVulnCounts(taskList) {
  const map = {}
  await Promise.all((taskList || []).map(async (t) => {
    try {
      const { data } = await http.get('/vuln', { params: { task_id: t.id, page: 1, page_size: 1 } })
      map[t.id] = data.total || 0
    } catch { map[t.id] = 0 }
  }))
  vulnCountMap.value = map
}

onMounted(async () => {
  const { data } = await http.get('/task', { params: { page: 1, page_size: 100 } })
  tasks.value = data.items
  await loadVulnCounts(tasks.value)
  syncFromRoute()
})
onBeforeUnmount(() => stopDeepPoll())
</script>

<style scoped>
.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.toolbar .hint { color: var(--text-dim); font-size: 12px; }
.dim { color: var(--text-dim); }
.small { font-size: 12px; }
.mono { font-family: Consolas, monospace; }
.name { color: var(--text-main); font-weight: 600; }
.waf-box {
  margin-top: 8px;
  padding: 8px 10px;
  border: 1px dashed var(--border-dim);
  border-radius: 6px;
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}
.m-GET { color: #67c23a; font-weight: 600; }
.m-POST { color: #e6a23c; font-weight: 600; }
.task-url-list { display: flex; flex-direction: column; gap: 10px; }
.task-url-card {
  border: 1px solid #30363d; border-radius: 8px; padding: 12px 14px; cursor: pointer;
  transition: border-color .15s, background .15s;
}
.task-url-card:hover { border-color: #58a6ff; background: #161b22; }
.task-url-card .row1 { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; }
.task-url-card .url { color: #58a6ff; font-size: 13px; word-break: break-all; }
.target-banner {
  padding: 8px 10px; background: #0d1117; border-radius: 6px;
  color: #58a6ff; word-break: break-all;
}
.vuln-head {
  padding: 14px; background: #0f141a;
  border: 1px solid var(--border-dim); border-radius: 10px;
}
.vh-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.vuln-head h3 { margin: 0; color: var(--text-main); font-size: 15px; line-height: 1.4; }
.vh-tags { display: flex; gap: 6px; flex: 0 0 auto; }
.key-facts {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
  margin-top: 12px; padding: 0; background: transparent; border-radius: 0;
}
.kf-item {
  min-width: 0; padding: 9px 11px; background: var(--bg-panel);
  border: 1px solid var(--border-dim); border-radius: 8px;
}
.kf-item > div { margin-top: 3px; color: var(--text-main); font-size: 12.5px; }
.payload-box, .deep-box {
  padding: 12px; border-radius: 8px; margin-top: 10px; background: #0f141a;
}
.payload-box {
  border: 1px solid rgba(255, 107, 138, .32);
  border-left: 3px solid #ff6b8a;
}
.payload-box pre {
  margin: 6px 0 0; white-space: pre-wrap; color: #ffc0cf;
  max-height: 160px; overflow: auto; font-size: 12.5px;
}
.deep-box {
  border: 1px solid rgba(230, 162, 60, .3);
  border-left: 3px solid #e8bb6b;
}
.deep-box pre {
  margin: 6px 0 0; white-space: pre-wrap; color: #e6d3b0;
  max-height: 200px; overflow: auto; font-size: 12.5px;
}
.ev-sec-title {
  position: relative; padding-left: 10px;
  margin-top: 16px; color: var(--text-main); font-size: 14px; font-weight: 600;
}
.ev-sec-title::before {
  content: ""; position: absolute; left: 0; top: 50%;
  width: 3px; height: 12px; margin-top: -6px;
  border-radius: 2px; background: var(--grad);
}
.process-collapse { margin-top: 12px; }
.ev-card {
  padding: 10px 12px; background: #0f141a;
  border: 1px solid var(--border-dim); border-radius: 8px;
}
.ev-head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 6px; }
.ev-stage { color: #9cc0ff; font-size: 12px; }
.ev-content {
  margin: 0; max-height: 220px; overflow: auto; white-space: pre-wrap;
  word-break: break-all; color: #c9d1d9; font-size: 12px; line-height: 1.6;
}
.ev-foot { margin-top: 6px; }
.advice {
  margin-top: 18px; padding: 14px; background: #0f141a;
  border: 1px solid var(--border-dim); border-radius: 10px;
}
.advice h4 { color: var(--text-main); margin: 0 0 8px; font-size: 14px; }
.advice li { color: #c9d1d9; font-size: 13px; margin-bottom: 4px; line-height: 1.6; }
.deep-modes { display: flex; flex-direction: column; gap: 10px; margin: 14px 0; width: 100%; }
.deep-result { margin-top: 10px; padding: 8px 10px; border-radius: 6px; background: rgba(64,158,255,.08); }
.deep-result-row { display: flex; gap: 10px; margin-top: 4px; }
.deep-result-row .dim { width: 96px; flex: none; }
.deep-collapse { margin-top: 8px; }
.deep-status { margin-top: 12px; padding: 10px; background: #0d1117; border-radius: 8px; }
.deep-log { margin-top: 8px; max-height: 160px; font-size: 12px; color: #c9d1d9; }
</style>
