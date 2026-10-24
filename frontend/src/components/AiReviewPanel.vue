<template>
  <div>
    <div class="toolbar">
      <el-radio-group v-model="tab" size="small" @change="reload">
        <el-radio-button value="all">全部研判</el-radio-button>
        <el-radio-button value="queue">待复核</el-radio-button>
      </el-radio-group>
      <el-button size="small" @click="reload">刷新</el-button>
      <span class="dim small">DeepSeek 对该任务已采集接口的风险判断；点「查看思考」看完整理由</span>
    </div>

    <el-table :data="items" v-loading="loading" stripe>
      <el-table-column prop="assessment_id" label="ID" width="60" />
      <el-table-column prop="method" label="方法" width="70">
        <template #default="{ row }">
          <span :class="'m-' + row.method">{{ row.method }}</span>
        </template>
      </el-table-column>
      <el-table-column label="接口" min-width="160">
        <template #default="{ row }">
          <span class="ellipsis" :title="row.path">{{ row.path }}</span>
        </template>
      </el-table-column>
      <el-table-column label="路由" width="110" v-if="tab === 'all'">
        <template #default="{ row }">
          <el-tag size="small" :type="routeType(row.route)">{{ routeLabel(row.route) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="风险分" width="120">
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
      <el-table-column label="思考摘要" min-width="220">
        <template #default="{ row }">
          <span class="ellipsis small">{{ (row.reasons || []).join('；') || '-' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" :width="tab === 'queue' ? 280 : 110" fixed="right">
        <template #default="{ row }">
          <el-button size="small" type="primary" plain @click="openThought(row)">查看思考</el-button>
          <template v-if="tab === 'queue'">
            <el-button size="small" type="primary" @click="review(row, 'confirm')">确认扫描</el-button>
            <el-button size="small" type="danger" plain @click="review(row, 'false_positive')">误报</el-button>
          </template>
        </template>
      </el-table-column>
    </el-table>

    <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
                   layout="total, prev, pager, next" @current-change="load"
                   style="margin-top: 10px" />

    <el-drawer v-model="thoughtDlg" size="440px"
               :title="`DeepSeek 思考 · ${thought?.method || ''} ${thought?.path || ''}`">
      <template v-if="thought">
        <div class="meta-grid">
          <div><span class="dim">风险分</span><div class="mono">{{ Math.round(thought.risk_score) }}</div></div>
          <div><span class="dim">置信度</span><div class="mono">{{ (Number(thought.confidence) * 100).toFixed(0) }}%</div></div>
          <div><span class="dim">路由</span>
            <div><el-tag size="small" :type="routeType(thought.route)">{{ routeLabel(thought.route) }}</el-tag></div>
          </div>
          <div><span class="dim">引擎</span><div>{{ engineLabel(thought.model_info) }}</div></div>
        </div>
        <h4 class="sec-title">思考过程</h4>
        <ol v-if="thought.reasons?.length" class="thought-list">
          <li v-for="(r, i) in thought.reasons" :key="i">{{ r }}</li>
        </ol>
        <el-empty v-else description="无思考内容" :image-size="56" />
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import http from '../api/http'

const props = defineProps({
  taskId: { type: [Number, String], required: true },
})

const tab = ref('all')
const items = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = 15
const loading = ref(false)
const thoughtDlg = ref(false)
const thought = ref(null)
let resumeAsked = false

function routeLabel(r) {
  return { auto_pass: '自动放行', manual_review: '待人工复核', suspicious: '存疑深测' }[r] || (r || '-')
}
function routeType(r) {
  return { auto_pass: 'success', manual_review: 'warning', suspicious: 'danger' }[r] || 'info'
}
function engineLabel(info) {
  if (!info) return '-'
  if (info.provider === 'rule-engine') return '规则引擎'
  return info.model || info.provider || 'AI'
}
function scoreColor(s) {
  if (s >= 70) return '#f56c6c'
  if (s >= 40) return '#e6a23c'
  return '#67c23a'
}

function reload() { page.value = 1; load() }

async function load() {
  if (!props.taskId) return
  loading.value = true
  try {
    const url = tab.value === 'queue' ? '/ai/review-queue' : '/ai/assessments'
    const { data } = await http.get(url, {
      params: { task_id: props.taskId, page: page.value, page_size: pageSize },
    })
    items.value = data.items
    total.value = data.total
    if (tab.value === 'queue' && !data.items.length && !data.total) await autoResume()
  } finally { loading.value = false }
}

async function autoResume() {
  if (!props.taskId || resumeAsked) return
  resumeAsked = true
  try {
    const { data } = await http.post('/scan/resume', { task_id: Number(props.taskId) })
    ElMessage.success(`已恢复扫描（${data.scanned} 个接口）`)
  } catch { resumeAsked = false }
}

function openThought(row) {
  thought.value = row
  thoughtDlg.value = true
}

async function review(row, action) {
  await http.post(`/ai/review/${row.assessment_id}`, { action })
  ElMessage.success(action === 'confirm' ? '已确认，将进入探测队列' : '已标记误报')
  await load()
}

watch(() => props.taskId, () => { resumeAsked = false; reload() })
onMounted(reload)

defineExpose({ reload })
</script>

<style scoped>
.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.dim { color: var(--text-dim); }
.small { font-size: 12px; }
.mono { font-family: Consolas, monospace; }
.m-GET { color: #67c23a; font-weight: 600; }
.m-POST { color: #e6a23c; font-weight: 600; }
.meta-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 10px 14px;
  margin-bottom: 14px; padding: 10px; background: #0d1117; border-radius: 8px;
}
.sec-title { margin: 12px 0 8px; color: var(--text-main); font-size: 14px; }
.thought-list { margin: 0; padding-left: 20px; color: var(--text-main); line-height: 1.7; }
.thought-list li { margin-bottom: 6px; }
</style>
