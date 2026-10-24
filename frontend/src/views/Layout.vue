<template>
  <el-container class="layout-root">
    <!-- 侧边导航：整列固定高度，菜单区独立滚动，作者信息固定在底部 -->
    <el-aside width="210px" class="sidebar">
      <div class="brand">
        <span class="logo">⌖</span>
        <div class="brand-text">
          <div class="brand-name">mhszed-sql</div>
          <div class="brand-sub">Web Security Testing</div>
        </div>
      </div>
      <el-menu
        class="side-menu"
        router
        :default-active="active"
        background-color="transparent"
        text-color="#8b949e"
        active-text-color="#4f8cff"
      >
        <el-menu-item index="/tasks"><el-icon><Monitor /></el-icon>任务面板</el-menu-item>
        <el-menu-item index="/collect"><el-icon><Connection /></el-icon>接口采集</el-menu-item>
        <el-menu-item index="/vulns"><el-icon><Warning /></el-icon>漏洞结果</el-menu-item>
        <el-menu-item index="/audit"><el-icon><Document /></el-icon>审计日志</el-menu-item>
        <el-menu-item index="/config"><el-icon><Setting /></el-icon>扫描配置</el-menu-item>
        <el-menu-item index="/kb"><el-icon><Collection /></el-icon>知识库</el-menu-item>
      </el-menu>
      <div class="side-footer">
        <div class="author">作者：mhszed 与 Lianhaorui</div>
        <div class="foot-links">
          <a href="https://github.com/mhszed/" target="_blank" rel="noopener">作者主页</a>
          <span class="dot">·</span>
          <a href="https://github.com/mhszed/mhszed-sql" target="_blank" rel="noopener">最新版下载</a>
        </div>
        <div class="disclaimer">
          本工具仅限学习与授权靶场测试，严禁用于未授权的实战环境。
          因滥用产生的一切后果由使用者本人承担，与作者无关。
        </div>
      </div>
    </el-aside>

    <el-container class="layout-body">
      <!-- 顶栏 -->
      <el-header class="topbar">
        <div class="topbar-title">{{ route.meta.title || '' }}</div>
        <div class="topbar-right">
          <el-dropdown trigger="click" @command="onUserCommand">
            <span class="who user-trigger">
              {{ auth.username }}（{{ auth.role }}）<span class="caret">▾</span>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="password">修改密码</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>

    <!-- 修改密码 -->
    <el-dialog v-model="pwdDlg" title="修改密码" width="420px" append-to-body>
      <el-form label-width="96px" @submit.prevent>
        <el-form-item label="当前密码">
          <el-input v-model="pwd.current" type="password" show-password
                    autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwd.next" type="password" show-password
                    autocomplete="new-password" />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input v-model="pwd.confirm" type="password" show-password
                    autocomplete="new-password" />
        </el-form-item>
      </el-form>
      <div class="pwd-hint">至少 6 位；修改后请使用新密码登录。</div>
      <template #footer>
        <el-button @click="pwdDlg = false">取消</el-button>
        <el-button type="primary" :loading="pwdSaving" @click="savePassword">保存</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Monitor, Connection, Setting, Warning, Collection, Document } from '@element-plus/icons-vue'
import { useAuth, logout } from '../composables/auth'
import http from '../api/http'

const route = useRoute()
const auth = useAuth()
const active = computed(() => '/' + (route.path.split('/')[1] || 'tasks'))

const pwdDlg = ref(false)
const pwdSaving = ref(false)
const pwd = reactive({ current: '', next: '', confirm: '' })

function onUserCommand(cmd) {
  if (cmd === 'logout') return onLogout()
  if (cmd === 'password') {
    pwd.current = ''
    pwd.next = ''
    pwd.confirm = ''
    pwdDlg.value = true
  }
}

async function savePassword() {
  if (!pwd.current) return ElMessage.warning('请输入当前密码')
  if (!pwd.next || pwd.next.length < 6) return ElMessage.warning('新密码至少 6 位')
  if (pwd.next !== pwd.confirm) return ElMessage.warning('两次输入的新密码不一致')
  if (pwd.next === pwd.current) return ElMessage.warning('新密码不能与当前密码相同')
  pwdSaving.value = true
  try {
    await http.post('/auth/change-password', {
      current_password: pwd.current,
      new_password: pwd.next,
    })
    ElMessage.success('密码已修改，请使用新密码登录')
    pwdDlg.value = false
  } catch { /* 错误提示由 http 拦截器统一处理 */ } finally {
    pwdSaving.value = false
  }
}

async function onLogout() {
  try { await http.post('/auth/logout') } catch { /* 后端失效也无妨 */ }
  logout()
}
</script>

<style scoped>
.layout-root {
  height: 100vh;
  overflow: hidden;
}
.sidebar {
  position: relative;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--bg-panel);
}
.brand, .side-menu, .side-footer { position: relative; z-index: 1; }
.brand {
  position: relative;
  display: flex;
  align-items: flex-end;
  gap: 8px;
  height: 84px;
  padding: 0 18px 12px;
  overflow: hidden;
  font-weight: 700;
  font-size: 16px;
  color: var(--text-main);
  flex: 0 0 auto;
  border-bottom: 1px solid var(--border-dim);
  background: var(--bg-panel);
}
/* 1.png 压暗后作为品牌背景，避免左上角比右侧更抢眼 */
.brand::before {
  content: "";
  position: absolute;
  inset: 0;
  /* contain：完整显示 1.png，不裁切 */
  background: url('/1.png') center / contain no-repeat;
  opacity: .17;
}
.brand::after {
  content: "";
  position: absolute;
  inset: 0;
  /* 只在底部轻压一层，保证文字可读，整体仍是淡背景 */
  background: linear-gradient(180deg, transparent 35%,
                                      rgba(13, 17, 23, .55) 100%);
}
.brand > * { position: relative; z-index: 2; }
.logo {
  color: var(--brand);
  font-size: 20px;
  filter: drop-shadow(0 2px 8px rgba(79, 140, 255, .45));
}
.brand-text { display: flex; flex-direction: column; line-height: 1.25; }
.brand-name {
  font-size: 16px;
  letter-spacing: .3px;
  text-shadow: 0 1px 8px rgba(0, 0, 0, .65);
}
.brand-sub {
  margin-top: 2px;
  font-size: 9.5px;
  font-weight: 500;
  letter-spacing: .5px;
  color: rgba(230, 237, 243, .58);
  text-transform: uppercase;
}
.side-menu {
  flex: 1 1 auto;
  overflow-y: auto;
  border-right: none;
  padding: 8px 10px;
}
.side-menu :deep(.el-menu-item) {
  position: relative;
  height: 42px;
  line-height: 42px;
  margin: 3px 0;
  border-radius: 8px;
  font-size: 13.5px;
  letter-spacing: .2px;
}
.side-menu :deep(.el-menu-item:hover) {
  background: rgba(79, 140, 255, .10) !important;
  color: #c9d1d9;
}
.side-menu :deep(.el-menu-item.is-active) {
  background: linear-gradient(90deg, rgba(79, 140, 255, .22),
                                      rgba(79, 140, 255, .05)) !important;
  color: #8ab4ff;
  font-weight: 600;
}
.side-menu :deep(.el-menu-item.is-active)::before {
  content: "";
  position: absolute;
  left: 0;
  top: 10px;
  bottom: 10px;
  width: 3px;
  border-radius: 0 3px 3px 0;
  background: var(--grad);
}
.side-footer {
  flex: 0 0 auto;
  padding: 12px 16px 14px;
  border-top: 1px solid var(--border-dim);
  background: rgba(13, 17, 23, .55);
  font-size: 11px;
  line-height: 1.7;
  color: var(--text-dim);
}
.author { margin-bottom: 2px; }
.foot-links {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}
.foot-links a {
  color: var(--brand);
  text-decoration: none;
  transition: color .15s;
}
.foot-links a:hover { color: var(--accent); text-decoration: underline; }
.disclaimer {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px dashed var(--border-dim);
  font-size: 10px;
  line-height: 1.6;
  color: var(--text-dim);
  opacity: .85;
}
.dot { opacity: .5; }

.layout-body { min-width: 0; }
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: rgba(22, 27, 34, .82);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--border-dim);
  height: 52px;
  flex: 0 0 52px;
  position: relative;
  z-index: 5;
}
.topbar-title {
  position: relative;
  padding-left: 10px;
  font-weight: 600;
  color: var(--text-main);
  letter-spacing: .2px;
}
.topbar-title::before {
  content: "";
  position: absolute;
  left: 0;
  top: 50%;
  width: 3px;
  height: 14px;
  margin-top: -7px;
  border-radius: 2px;
  background: linear-gradient(180deg, var(--brand), #e2366a);
}
/* 右侧内容区的迪亚波罗 / King Crimson 点缀：只在很低的透明度下出现 */
.topbar::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: -1px;
  height: 1px;
  background: linear-gradient(90deg, rgba(79, 140, 255, .55),
                                      rgba(226, 54, 106, .48) 65%, transparent);
}
.topbar-right { display: flex; align-items: center; gap: 10px; }
.who { color: var(--text-dim); font-size: 13px; }
.user-trigger {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 8px;
  border-radius: 6px;
  cursor: pointer;
  transition: background .15s;
}
.user-trigger:hover {
  background: #1f2630;
  box-shadow: inset 0 0 0 1px rgba(79, 140, 255, .25);
}
.caret { font-size: 10px; opacity: .65; }
.main {
  position: relative;
  flex: 1 1 auto;
  min-height: 0;
  padding: 0;
  overflow-y: auto;
  overflow-x: hidden;
  background:
    radial-gradient(1100px 500px at 85% -10%, rgba(79, 140, 255, .10), transparent 60%),
    radial-gradient(900px 520px at 100% 110%, rgba(226, 54, 106, .08), transparent 65%),
    var(--bg-page);
}
.main::after {
  content: "KING CRIMSON";
  position: fixed;
  right: 24px;
  bottom: 14px;
  z-index: 0;
  font-size: 36px;
  font-weight: 800;
  font-style: italic;
  letter-spacing: 5px;
  color: rgba(226, 54, 106, .07);
  pointer-events: none;
  user-select: none;
}
.pwd-hint {
  color: var(--text-dim);
  font-size: 12px;
  padding-left: 96px;
}
</style>
