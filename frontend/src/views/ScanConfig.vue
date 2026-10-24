<template>
  <div class="page-wrap">
    <h2 class="page-title">扫描配置</h2>

    <el-row :gutter="14">
      <!-- 左：授权范围 -->
      <el-col :span="12">
        <el-card class="panel-card">
          <template #header>
            <div class="card-head">
              <span>授权范围</span>
              <el-button size="small" type="primary" @click="scopeDlg = true">＋ 添加</el-button>
            </div>
          </template>
          <p class="dim small" style="margin-top: 0">
            只有落在授权范围内的目标才允许测试（安全管控硬约束）。
          </p>
          <el-table :data="scopes" v-loading="scopeLoading" size="small">
            <el-table-column prop="name" label="名称" width="120" />
            <el-table-column label="类型" width="90">
              <template #default="{ row }">
                <el-tag size="small">{{ row.scope_type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="scope_value" label="范围" min-width="140">
              <template #default="{ row }">
                <span class="ellipsis mono small">{{ row.scope_value }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="70">
              <template #default="{ row }">
                <el-button size="small" type="danger" text @click="delScope(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <!-- 右：AI 与工具设置 -->
      <el-col :span="12">
        <el-card class="panel-card">
          <template #header>
            <div class="card-head">
              <span>AI 接入与工具</span>
              <el-tag v-if="settings.ai_configured" type="success" size="small">已配置</el-tag>
              <el-tag v-else type="info" size="small">未配置 · 规则引擎降级</el-tag>
            </div>
          </template>
          <el-form label-width="110px" style="max-width: 480px">
            <el-form-item label="Base URL">
              <el-input v-model="ai.base_url" placeholder="https://api.xxx.com/v1" />
            </el-form-item>
            <el-form-item label="API Key">
              <el-input v-model="ai.api_key" type="password" show-password
                        :placeholder="settings.ai_configured ? '已配置（密钥不回显，输入新值可覆盖）' : 'sk-…'" />
            </el-form-item>
            <el-form-item label="模型">
              <el-input v-model="ai.model" placeholder="gpt-4o / deepseek-chat …" />
            </el-form-item>
            <el-form-item label="SQLMap 路径">
              <el-input v-model="sqlmapPath" placeholder="留空则用项目内置 tools/sqlmap（1.9.8），再退 PATH" />
            </el-form-item>
            <el-button type="primary" :loading="saving" @click="saveSettings">保存设置</el-button>
            <el-button type="success" plain :loading="testing" @click="testAI">测试连接</el-button>
          </el-form>
          <el-alert v-if="testResult" :type="testResult.ok ? 'success' : 'error'"
                    :closable="false" style="margin-top: 10px"
                    :title="testResult.ok
                      ? `连接成功：${testResult.model}（${testResult.elapsed_ms}ms）`
                      : `连接失败${testResult.status ? ' · HTTP ' + testResult.status : ''}：${testResult.error || ''}`"
                    :description="testResult.ok
                      ? (testResult.reply || '')
                      : `${testResult.base_url || ''}${testResult.hint ? '  |  ' + testResult.hint : ''}`" />
          <p class="dim small">
            兼容 OpenAI 接口协议；API Key 加密存储、不回显。未配置时系统走内置规则引擎（无 key 降级）。
          </p>
        </el-card>
      </el-col>
    </el-row>

    <!-- 说明区 -->
    <el-card class="panel-card" style="margin-top: 14px">
      <template #header>任务级扫描参数（创建任务时选择）</template>
      <div class="dim small">
        <p>· 探测强度 low / medium / high → sqlmap level 1-3 / risk 1-2，探针节奏与限速随之收紧。</p>
        <p>· 探测引擎：SQLMap 初筛 + AI Payload 精细化可独立开关；写接口自动限制 technique=BET（禁 UNION 脱数、禁堆叠）。</p>
        <p>· 安全管控：统一 SafeHttpClient 出口（限速滑动窗口 + 三态熔断 + 越界拦截），高危动作全部落审计日志。</p>
      </div>
    </el-card>

    <!-- 新增范围 -->
    <el-dialog v-model="scopeDlg" title="添加授权范围" width="480">
      <el-form :model="scopeForm" label-width="90px">
        <el-form-item label="名称">
          <el-input v-model="scopeForm.name" placeholder="例：xx-SRC 主站" />
        </el-form-item>
        <el-form-item label="类型">
          <el-radio-group v-model="scopeForm.scope_type">
            <el-radio value="domain">域名</el-radio>
            <el-radio value="wildcard">通配符</el-radio>
            <el-radio value="ip">IP</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="范围值">
          <el-input v-model="scopeForm.scope_value"
                    placeholder="example.com / *.example.com / 1.2.3.4（不要带 http:// 和端口）" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="scopeForm.note" placeholder="授权依据 / 有效期说明（可选）" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="scopeDlg = false">取消</el-button>
        <el-button type="primary" @click="addScope">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { reactive, ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import http from '../api/http'

const scopes = ref([])
const scopeLoading = ref(false)
const scopeDlg = ref(false)
const scopeForm = reactive({ name: '', scope_type: 'domain', scope_value: '', note: '' })

const settings = ref({})
const ai = reactive({ base_url: '', api_key: '', model: '' })
const sqlmapPath = ref('')
const saving = ref(false)
const testing = ref(false)
const testResult = ref(null)

async function loadScopes() {
  scopeLoading.value = true
  try {
    const { data } = await http.get('/scope')
    scopes.value = data.items
  } finally { scopeLoading.value = false }
}

async function addScope() {
  if (!scopeForm.name || !scopeForm.scope_value) {
    ElMessage.warning('请填写名称与范围值'); return
  }
  await http.post('/scope', { ...scopeForm })
  ElMessage.success('已添加')
  scopeDlg.value = false
  scopeForm.name = ''; scopeForm.scope_value = ''; scopeForm.note = ''
  loadScopes()
}

async function delScope(row) {
  await ElMessageBox.confirm(`删除范围「${row.name}」？`, '确认', { type: 'warning' })
  await http.delete(`/scope/${row.id}`)
  ElMessage.success('已删除'); loadScopes()
}

async function loadSettings() {
  const { data } = await http.get('/settings')
  settings.value = data
  ai.base_url = data.items['ai.base_url'] || ''
  // 密钥不回显：后端返回 "<configured>" 哨兵 → 输入框留空，仅提示已有密钥
  ai.api_key = ''
  ai.model = data.items['ai.model'] || ''
  sqlmapPath.value = data.items['sqlmap.path'] || ''
}

async function testAI() {
  testing.value = true
  testResult.value = null
  try {
    // 传入当前输入框的值（未填的字段由后端回退到已保存配置）
    const { data } = await http.post('/settings/test-ai', {
      base_url: ai.base_url || undefined,
      api_key: ai.api_key || undefined,
      model: ai.model || undefined,
    })
    testResult.value = data
    if (data.ok) ElMessage.success('AI 连接成功')
    else ElMessage.error('AI 连接失败，详见下方提示')
  } catch { /* interceptor 已提示 */ } finally { testing.value = false }
}

async function saveSettings() {
  saving.value = true
  try {
    const jobs = []
    const put = (key, value, is_secret = false) =>
      jobs.push(http.put('/settings', { key, value, is_secret }))
    if (ai.base_url) put('ai.base_url', ai.base_url)
    // 留空 = 保持现有密钥不动；输入新值才覆盖
    if (ai.api_key) put('ai.api_key', ai.api_key, true)
    if (ai.model) put('ai.model', ai.model)
    if (sqlmapPath.value) put('sqlmap.path', sqlmapPath.value)
    await Promise.all(jobs)
    ElMessage.success('设置已保存')
    loadSettings()
  } finally { saving.value = false }
}

onMounted(() => { loadScopes(); loadSettings() })
</script>

<style scoped>
.card-head { display: flex; align-items: center; gap: 8px; justify-content: space-between; }
.dim { color: var(--text-dim); }
.small { font-size: 12.5px; }
.mono { font-family: Consolas, monospace; }
</style>
