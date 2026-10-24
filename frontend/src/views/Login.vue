<template>
  <div class="login-bg">
    <el-card class="login-card">
      <div class="login-title">mhszed-sql</div>
      <div class="login-sub">全链路 Web 安全测试系统</div>
      <el-form :model="form" @submit.prevent="doLogin">
        <el-form-item>
          <el-input v-model="form.username" placeholder="用户名" size="large" autofocus />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" placeholder="密码"
                    size="large" show-password @keyup.enter="doLogin" />
        </el-form-item>
        <el-button type="primary" size="large" style="width: 100%" :loading="loading" @click="doLogin">
          登 录
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import http from '../api/http'
import { setLogin } from '../composables/auth'

const router = useRouter()
const route = useRoute()
const form = reactive({ username: '', password: '' })
const loading = ref(false)

async function doLogin() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入用户名与密码')
    return
  }
  loading.value = true
  try {
    const { data } = await http.post('/auth/login', {
      username: form.username, password: form.password,
    })
    setLogin(data)
    router.push(route.query.redirect || '/')
  } catch { /* http 拦截器已提示 */ } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-bg {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: radial-gradient(ellipse at 30% 20%, #14233f 0%, #0d1117 60%);
}
.login-card {
  width: 360px;
  background: rgba(22, 27, 34, .86);
  backdrop-filter: blur(14px);
  border: 1px solid var(--border-dim);
  border-radius: 14px;
  box-shadow: 0 24px 70px rgba(0, 0, 0, .55);
}
.login-title { font-size: 22px; font-weight: 700; color: var(--text-main); text-align: center; }
.login-sub { font-size: 13px; color: var(--text-dim); text-align: center; margin: 6px 0 20px; }
</style>
