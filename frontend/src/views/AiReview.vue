<template>
  <div class="page-wrap">
    <h2 class="page-title">AI 研判</h2>

    <el-card class="panel-card">
      <div class="toolbar">
        <el-select v-model="taskId" placeholder="选择任务" filterable style="width: 300px"
                   @change="onTaskChange">
          <el-option v-for="t in tasks" :key="t.id"
                     :label="`#${t.id} ${t.name}（${statusLabel(t.status)}）`" :value="t.id" />
        </el-select>
        <el-radio-group v-model="tab" @change="reload">
          <el-radio-button value="queue">待复核</el-radio-button>
          <el-radio-button value="all">全部研判（含思考）</el-radio-button>
        </el-radio-group>
        <el-button @click="reload" :disabled="!taskId">刷新</el-button>
        <span class="hint">
          DeepSeek 的思考写在「研判理由」里；点「查看思考」看完整分析
        </span>
      </div>

      <el-empty v-if="!taskId" description="选择任务查看研判结果" />

      <template v-else>
        <el-table :data="items" v-loading="loading" stripe>
          <el-table-column prop="assessment_id" label="ID" width="60" />
          <el-table-column prop="method" label="方法" width="70">
            <template #default="{ row }">
              <span :class="'m-' + row.method">{{ row.method }}</span>
            </template>
          </el-table-column>
          <el-table-column label="接口" min-width="180">
            <template #default="{ row }">
              <span class="ellipsis" :title="row.path">{{ row.path }}</span>
            </template>
          </el-table-column>
          <el-table-column label="路由" width="110" v-if="tab === 'all'">
            <template #default="{ row }">
              <el-tag size="small" :type="routeType(row.route)">{{ routeLabel(row.route) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="风险分" width="130">
            <template #default="{ row }">
              <el-progress :percentage="Math.round(row.risk_score)" :stroke-width="10"
                          :color="scoreColor(row.risk_score)" />
            </template>
          </el-table-column>
          <el-table-column label="置信度" width="80">
            <template #default="{ row }">
              <span class="mono">{{ (Number(row.confidence) * 100).toFixed(0) }}%</span>
            </template>
          </el-table-column>
          <el-table-column label="DeepSeek 思考摘要" min-width="240">
            <template #default="{ row }">
              <span class="ellipsis small" :title="(row.reasons || []).join('；')">
                {{ (row.reasons || []).join('；') || '（无理由，可能是规则引擎）' }}
              </span>
            </template>
          </el-table-column>
          <el-table-column label="引擎" width="120">
            <template #default="{ row }">
              <span class="dim small">{{ engineLabel(row.model_info) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" :width="tab === 'queue' ? 280 : 120" fixed="right">
            <template #default="{ row }">
              <el-button size="small" type="primary" plain @click="openThought(row)">查看思考</el-button>
              <template v-if="tab === 'queue'">
                <el-button size="small" type="primary" @click="review(row, 'confirm')">确认扫描</el-button>
                <el-button size="small" type="danger" plain
                           @click="review(row, 'false_positive')">误报</el-button>
                <el-button size="small" @click="openAdjust(row)">调整</el-button>
              </template>
            </template>
          </el-table-column>
        </el-table>

        <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
                       layout="total, prev, pager, next" @current-change="load" />
      </template>
    </el-card>

    <!-- DeepSeek 思考详情 -->
    <el-drawer v-model="thoughtDlg" size="480px"
               :title="`DeepSeek 思考 · ${thought?.method || ''} ${thought?.path || ''}`">
      <template v-if="thought">
        <div class="meta-grid">
          <div><span class="dim">研判 ID</span><div>#{{ thought.assessment_id }}</div></div>
          <div><span class="dim">路由</span>
            <div><el-tag size="small" :type="routeType(thought.route)">{{ routeLabel(thought.route) }}</el-tag></div>
          </div>
          <div><span class="dim">风险分</span><div class="mono">{{ Math.round(thought.risk_score) }}</div></div>
          <div><span class="dim">置信度</span><div class="mono">{{ (Number(thought.confidence) * 100).toFixed(0) }}%</div></div>
          <div><span class="dim">引擎</span><div>{{ engineLabel(thought.model_info) }}</div></div>
          <div><span class="dim">Tokens</span><div class="mono">{{ thought.model_info?.tokens ?? '-' }}</div></div>
        </div>

        <h4 class="sec-title">思考过程（reasons）</h4>
        <ol v-if="thought.reasons?.length" class="thought-list">
          <li v-for="(r, i) in thought.reasons" :key="i">{{ r }}</li>
        </ol>
        <el-empty v-else description="无思考内容（规则引擎或空返回）" :image-size="64" />

        <h4 class="sec-title">原始 model_info</h4>
        <pre class="raw mono">{{ JSON.stringify(thought.model_info || {}, null, 2) }}</pre>

        <div v-if="tab === 'queue'" class="drawer-actions">
          <el-button type="primary" @click="review(thought, 'confirm'); thoughtDlg = false">确认扫描</el-button>
          <el-button type="danger" plain @click="review(thought, 'false_positive'); thoughtDlg = false">误报</el-button>
        </div>
      </template>
    </el-drawer>

    <el-dialog v-model="adjustDlg" title="调整风险分" width="420">
      <p class="dim">调整后重新路由：低分直接放行扫描，高分维持人工复核。</p>
      <el-slider v-model="adjustScore" :min="0" :max="100" show-input />
      <template #footer>
        <el-button @click="adjustDlg = false">取消</el-button>
        <el-button type="primary" @click="doAdjust">提交</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute } from 'vue-router'
import http from '../api/http'

const route = useRoute()
const tasks = ref([])
const taskId = ref(null)
const tab = ref('all')          // 默认看全部，才能看到 suspicious 的 DeepSeek 思考
const items = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 15
const loading = ref(false)

const thoughtDlg = ref(false)
const thought = ref(null)
const adjustDlg = ref(false)
const adjustScore = ref(50)
const adjustRow = ref(null)

const STATUS_LABEL = { created: '已创建', pending: '已创建', collecting: '采集中', scanning: '扫描中',
                       review: '待研判', done: '完成', stopped: '已终止', terminated: '已终止', error: '异常' }
function statusLabel(s) { return STATUS_LABEL[s] || s }

function routeLabel(r) {
  return { auto_pass: '自动放行', manual_review: '待人工复核', suspicious: '存疑深测' }[r] || (r || '-')
}
function routeType(r) {
  return { auto_pass: 'success', manual_review: 'warning', suspicious: 'danger' }[r] || 'info'
}
function engineLabel(info) {
  if (!info) return '-'
  if (typeof info === 'string') return info
  if (info.provider === 'rule-engine') return '规则引擎'
  return info.model || info.provider || 'AI'
}

function onTaskChange() { reload() }
function reload() { page.value = 1; load() }

async function load() {
  if (!taskId.value) return
  loading.value = true
  try {
    const url = tab.value === 'queue' ? '/ai/review-queue' : '/ai/assessments'
    const { data } = await http.get(url, {
      params: { task_id: taskId.value, page: page.value, page_size: pageSize },
    })
    items.value = data.items
    total.value = data.total
    if (tab.value === 'queue' && !data.items.length && !data.total) await autoResume()
  } finally { loading.value = false }
}

let resumeAsked = false
async function autoResume() {
  if (!taskId.value || resumeAsked) return
  const task = tasks.value.find(t => t.id === taskId.value)
  if (task && task.status !== 'review') return
  resumeAsked = true
  try {
    const { data } = await http.post('/scan/resume', { task_id: taskId.value })
    ElMessage.success(`已恢复扫描（${data.scanned} 个接口），可回任务面板看实时日志`)
  } catch { resumeAsked = false }
}

function openThought(row) {
  thought.value = row
  thoughtDlg.value = true
}

async function review(row, action) {
  await http.post(`/ai/review/${row.assessment_id}`, { action })
  ElMessage.success(action === 'confirm' ? '已确认，将进入探测队列' : '已标记误报，回流负样本库')
  await load()
}

function openAdjust(row) {
  adjustRow.value = row
  adjustScore.value = Math.round(row.risk_score)
  adjustDlg.value = true
}

async function doAdjust() {
  await http.post(`/ai/review/${adjustRow.value.assessment_id}`, {
    action: 'adjust', adjusted_score: adjustScore.value,
  })
  ElMessage.success('已调整风险分')
  adjustDlg.value = false
  load()
}

function scoreColor(s) {
  if (s >= 70) return '#f56c6c'
  if (s >= 40) return '#e6a23c'
  return '#67c23a'
}

onMounted(async () => {
  const { data } = await http.get('/task', { params: { page: 1, page_size: 100 } })
  tasks.value = data.items
  const preset = Number(route.params.taskId)
  if (preset && tasks.value.some(t => t.id === preset)) taskId.value = preset
  else if (tasks.value.length) taskId.value = tasks.value[0].id
  if (taskId.value) load()
})
</script>

<style scoped>
.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.toolbar .hint { color: var(--text-dim); font-size: 12px; }
.dim { color: var(--text-dim); }
.small { font-size: 12px; }
.mono { font-family: Consolas, monospace; }
.m-GET { color: #67c23a; font-weight: 600; }
.m-POST { color: #e6a23c; font-weight: 600; }
.meta-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 12px 16px;
  margin-bottom: 18px; padding: 12px; background: #0d1117; border-radius: 8px;
}
.sec-title { margin: 16px 0 8px; color: var(--text-main); font-size: 14px; }
.thought-list { margin: 0; padding-left: 20px; color: var(--text-main); line-height: 1.7; }
.thought-list li { margin-bottom: 8px; }
.raw {
  background: #0d1117; padding: 10px; border-radius: 6px; color: #7ee787;
  white-space: pre-wrap; word-break: break-all; font-size: 12px;
}
.drawer-actions { margin-top: 20px; display: flex; gap: 8px; }
</style>
