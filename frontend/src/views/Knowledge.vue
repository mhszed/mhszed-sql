<template>
  <div class="page-wrap">
    <h2 class="page-title">知识库</h2>

    <el-tabs v-model="tab">
      <el-tab-pane label="Payload 库" name="payloads">
        <div class="toolbar">
          <el-select v-model="pq.vector" placeholder="向量" clearable style="width: 130px" @change="preLoad">
            <el-option label="布尔盲注" value="boolean" /><el-option label="时间盲注" value="time" />
            <el-option label="报错注入" value="error" /><el-option label="UNION" value="union" />
          </el-select>
          <el-select v-model="pq.waf" placeholder="目标 WAF" clearable style="width: 150px" @change="preLoad">
            <el-option v-for="w in WAF_PRODUCTS" :key="w" :label="w" :value="w" />
          </el-select>
          <el-button type="primary" @click="openEdit()">＋ 新增 Payload</el-button>
          <span class="hint">
            供 AI 模仿生成用：入库的是「参数值形态」与测试思路标签，不是死记整篇文章。
            破坏性语句会被拒绝。
          </span>
        </div>

        <el-table :data="payloads" v-loading="pl" stripe>
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="Payload" min-width="260">
            <template #default="{ row }">
              <span class="mono small ellipsis" :title="row.payload">{{ row.payload }}</span>
            </template>
          </el-table-column>
          <el-table-column label="向量" width="80">
            <template #default="{ row }"><el-tag size="small">{{ row.vector }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="target_waf" label="目标WAF" width="100">
            <template #default="{ row }">{{ row.target_waf || '通用' }}</template>
          </el-table-column>
          <el-table-column prop="dbms" label="DBMS" width="100">
            <template #default="{ row }">{{ row.dbms || '-' }}</template>
          </el-table-column>
          <el-table-column label="标签" min-width="140">
            <template #default="{ row }">
              <el-tag v-for="t in (row.bypass_tags || [])" :key="t" size="small" style="margin:1px">{{ t }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="绕过记录" width="150">
            <template #default="{ row }">
              <el-tag v-if="row.target_waf" size="small" type="danger">
                已绕过 {{ row.target_waf }}
              </el-tag>
              <el-tag v-else-if="row.success_count" size="small" type="success">
                已验证可用
              </el-tag>
              <span v-else class="dim small">未验证</span>
              <span v-if="row.success_count" class="dim small" style="margin-left:4px">
                ×{{ row.success_count }}
              </span>
            </template>
          </el-table-column>
          <el-table-column label="来源" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.source === 'manual' ? 'info' : 'success'">{{ row.source }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="启用" width="70">
            <template #default="{ row }">
              <el-switch :model-value="row.is_active" @change="toggle(row)" />
            </template>
          </el-table-column>
          <el-table-column label="操作" width="130" fixed="right">
            <template #default="{ row }">
              <el-button size="small" @click="openEdit(row)">编辑</el-button>
              <el-button size="small" type="danger" text @click="del(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-pagination v-model:current-page="pPage" :page-size="pageSize" :total="pTotal"
                       layout="total, prev, pager, next" @current-change="loadPayloads" />
      </el-tab-pane>

      <el-tab-pane label="误报样本（负样本）" name="fps">
        <div class="toolbar">
          <span class="hint">漏洞复核判误报后自动回流；研判时前置检索命中即压制风险分</span>
        </div>
        <el-table :data="fps" v-loading="fl" stripe>
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column label="接口签名" min-width="220">
            <template #default="{ row }">
              <span class="mono small ellipsis" :title="row.endpoint_signature">{{ row.endpoint_signature }}</span>
            </template>
          </el-table-column>
          <el-table-column label="误报原因" min-width="180">
            <template #default="{ row }"><span class="small">{{ row.reason || '-' }}</span></template>
          </el-table-column>
          <el-table-column label="压制次数" width="90">
            <template #default="{ row }">{{ row.hit_count }}</template>
          </el-table-column>
          <el-table-column label="创建时间" width="160">
            <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
          </el-table-column>
        </el-table>
        <el-pagination v-model:current-page="fPage" :page-size="pageSize" :total="fTotal"
                       layout="total, prev, pager, next" @current-change="loadFps" />
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="dlg" :title="editRow ? `编辑 Payload #${editRow.id}` : '新增 Payload'" width="560">
      <el-form :model="form" label-width="90px">
        <el-form-item label="向量">
          <el-radio-group v-model="form.vector">
            <el-radio value="boolean">布尔</el-radio>
            <el-radio value="time">时间</el-radio>
            <el-radio value="error">报错</el-radio>
            <el-radio value="union">UNION</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="Payload">
          <el-input v-model="form.payload" type="textarea" :rows="3" maxlength="2000"
                    placeholder="例：1' and '1'='1" />
        </el-form-item>
        <el-form-item label="目标 WAF">
          <el-select v-model="form.target_waf" clearable placeholder="通用" style="width: 200px">
            <el-option v-for="w in WAF_PRODUCTS" :key="w" :label="w" :value="w" />
          </el-select>
        </el-form-item>
        <el-form-item label="绕过标签">
          <el-select v-model="form.bypass_tags" multiple placeholder="测试思路标签" style="width: 320px">
            <el-option label="奇偶单引号" value="quote_parity" />
            <el-option label="注释闭合" value="comment_close" />
            <el-option label="内联注释" value="inline_comment" />
            <el-option label="编码" value="encoding" />
            <el-option label="空白符" value="whitespace" />
            <el-option label="大小写混淆" value="case" />
            <el-option label="排序注入" value="order_by" />
            <el-option label="JSON补引号" value="json_quote" />
          </el-select>
        </el-form-item>
        <el-form-item label="DBMS">
          <el-input v-model="form.dbms" placeholder="mysql / postgresql / sqlite（可选）" style="width: 220px" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dlg = false">取消</el-button>
        <el-button type="primary" @click="save">{{ editRow ? '保存' : '入库' }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { reactive, ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import http from '../api/http'

const WAF_PRODUCTS = ['阿里云WAF', '腾讯云WAF', '安全狗', 'D盾', '云锁', '宝塔WAF',
                      '长亭雷池', 'F5 BIG-IP', 'Cloudflare', 'AWS WAF', 'ModSecurity']

const tab = ref('payloads')
const pageSize = 15
const payloads = ref([])
const pPage = ref(1)
const pTotal = ref(0)
const pl = ref(false)
const pq = reactive({ vector: '', waf: '' })
const fps = ref([])
const fPage = ref(1)
const fTotal = ref(0)
const fl = ref(false)
const dlg = ref(false)
const editRow = ref(null)
const form = reactive({ payload: '', vector: 'boolean', target_waf: '', bypass_tags: [], dbms: '' })

function preLoad() { pPage.value = 1; loadPayloads() }

async function loadPayloads() {
  pl.value = true
  try {
    const params = { page: pPage.value, page_size: pageSize }
    if (pq.vector) params.vector = pq.vector
    if (pq.waf) params.waf = pq.waf
    const { data } = await http.get('/kb/payloads', { params })
    payloads.value = data.items
    pTotal.value = data.total
  } finally { pl.value = false }
}

async function loadFps() {
  fl.value = true
  try {
    const { data } = await http.get('/kb/false-positives', { params: { page: fPage.value, page_size: pageSize } })
    fps.value = data.items
    fTotal.value = data.total
  } finally { fl.value = false }
}

function openEdit(row) {
  editRow.value = row || null
  Object.assign(form, {
    payload: row?.payload || '', vector: row?.vector || 'boolean',
    target_waf: row?.target_waf || '', bypass_tags: row?.bypass_tags || [], dbms: row?.dbms || '',
  })
  dlg.value = true
}

async function save() {
  if (!form.payload) { ElMessage.warning('Payload 不能为空'); return }
  const body = {
    ...form,
    target_waf: form.target_waf || null,
    bypass_tags: form.bypass_tags.length ? form.bypass_tags : null,
    dbms: form.dbms || null,
  }
  try {
    if (editRow.value) {
      await http.put(`/kb/payloads/${editRow.value.id}`, body)
      ElMessage.success('已保存')
    } else {
      await http.post('/kb/payloads', body)
      ElMessage.success('已入库')
    }
    dlg.value = false
    loadPayloads()
  } catch { /* interceptor */ }
}

async function toggle(row) {
  const { data } = await http.post(`/kb/payloads/${row.id}/toggle`)
  row.is_active = data.is_active
}

async function del(row) {
  await ElMessageBox.confirm(`删除 Payload #${row.id}？`, '确认', { type: 'warning' })
  await http.delete(`/kb/payloads/${row.id}`)
  ElMessage.success('已删除'); loadPayloads()
}

function fmtTime(iso) {
  // 后端存 UTC ISO（带 Z）：必须真转本地时区（旧实现只替换字符串，UI 显 UTC 差 8 小时）
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
onMounted(() => { loadPayloads(); loadFps() })
</script>

<style scoped>
.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.toolbar .hint { color: var(--text-dim); font-size: 12px; }
.small { font-size: 12px; }
.mono { font-family: Consolas, monospace; }
</style>
