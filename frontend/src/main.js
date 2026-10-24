import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { router } from './router'
import App from './App.vue'

// Element Plus 深色主题（html.dark 类由 index.html 预置）
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import './styles/theme.css'
import './styles/overrides.css'

createApp(App).use(router).use(ElementPlus, { locale: zhCn }).mount('#app')
