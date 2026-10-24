import { ref } from 'vue'

/**
 * SSE 实时日志流封装（fetch + ReadableStream——EventSource 无法带 Authorization 头）。
 * 用法：
 *   const stream = useLogStream(maxLines = 500)
 *   stream.open(taskId)   // taskId 可空 = 全部日志；再次 open 会先关闭旧流
 *   stream.close()
 *   stream.lines / stream.connected
 */
export function useLogStream(maxLines = 500) {
  const lines = ref([])
  const connected = ref(false)
  const activeTask = ref(null)
  let ctrl = null

  async function open(taskId = null) {
    await close()
    lines.value = []   // 换任务时清空，避免串台
    activeTask.value = taskId
    ctrl = new AbortController()
    connected.value = true
    try {
      const qs = taskId != null ? `?task_id=${taskId}` : ''
      const resp = await fetch(`/api/scan/stream/logs${qs}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('mhszed_token')}`,
          Accept: 'text/event-stream',
          'Cache-Control': 'no-cache',
        },
        signal: ctrl.signal,
        cache: 'no-store',
      })
      if (!resp.ok || !resp.body) throw new Error(`SSE ${resp.status}`)
      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        // SSE 帧以空行分隔；只取 data: 行（心跳 / history-done 注释行自动忽略）
        const frames = buf.split('\n\n')
        buf = frames.pop() || ''
        for (const f of frames) {
          for (const line of f.split('\n')) {
            if (!line.startsWith('data:')) continue
            const raw = line.slice(5).trim()
            if (!raw) continue
            try {
              push(JSON.parse(raw))
            } catch { /* 忽略坏帧 */ }
          }
        }
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        push({ ts: new Date().toISOString(), channel: 'system', level: 'error',
               message: `日志流中断: ${e.message}` })
      }
    } finally {
      connected.value = false
    }
  }

  function push(ev) {
    lines.value.push(ev)
    if (lines.value.length > maxLines) lines.value.splice(0, lines.value.length - maxLines)
  }

  async function close() {
    if (ctrl) {
      ctrl.abort()
      ctrl = null
    }
    connected.value = false
  }

  return { lines, connected, activeTask, open, close }
}
