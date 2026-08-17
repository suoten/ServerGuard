<template>
  <div class="pricing-admin">
    <div class="page-card card">
      <div class="card-header">
        <h3>定价管理</h3>
        <el-button type="primary" :loading="saving" @click="handleSave">保存修改</el-button>
      </div>

      <el-alert
        title="免费转收费策略"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 24px"
      >
        <template #default>
          前期可将专业版/企业版标记为"即将上线"或"限时免费"。
          积累用户基础后，修改价格并取消"即将上线"标记即可开始收费。
          所有修改实时生效，无需重新部署。
        </template>
      </el-alert>

      <div class="plans-editor">
        <div v-for="(p, i) in pricing.plans" :key="i" class="plan-edit card">
          <div class="plan-edit-header">
            <h4>套餐 {{ i + 1 }}</h4>
            <el-switch v-model="p.enabled" active-text="启用" inactive-text="隐藏" />
          </div>
          <el-form label-position="top" class="plan-form">
            <div class="form-row">
              <el-form-item label="套餐名称">
                <el-input v-model="p.name" />
              </el-form-item>
              <el-form-item label="标签">
                <el-input v-model="p.tagline" />
              </el-form-item>
            </div>
            <div class="form-row">
              <el-form-item label="人民币价格">
                <el-input v-model="p.price_cny" placeholder="¥349 或 免费" />
              </el-form-item>
              <el-form-item label="USD 价格">
                <el-input v-model="p.price_usd" placeholder="$49" />
              </el-form-item>
              <el-form-item label="周期说明">
                <el-input v-model="p.period" placeholder="大版本永久" />
              </el-form-item>
            </div>
            <el-form-item label="备注">
              <el-input v-model="p.note" placeholder="当前大版本永久使用..." />
            </el-form-item>
            <el-form-item label="购买按钮文字">
              <el-input v-model="p.cta" placeholder="立即购买" />
            </el-form-item>
            <el-form-item label="是否标记'最受欢迎'">
              <el-switch v-model="p.popular" />
            </el-form-item>
            <el-form-item label="是否标记'即将上线'">
              <el-switch v-model="p.coming_soon" />
            </el-form-item>
            <el-form-item label="功能列表（每行一个）">
              <el-input
                v-model="p.features_text"
                type="textarea"
                :rows="6"
                placeholder="资源守护&#10;进程保活&#10;..."
              />
            </el-form-item>
          </el-form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { adminAPI } from '@/composables/useAPI'

const saving = ref(false)

const pricing = reactive({
  plans: [] as Array<{
    name: string; tagline: string; price_cny: string; price_usd: string;
    period: string; note: string; cta: string; popular: boolean;
    coming_soon: boolean; enabled: boolean; features_text: string
  }>,
})

onMounted(async () => {
  try {
    const resp = await adminAPI.getPricing()
    pricing.plans = resp.data.plans || []
  } catch {
    // Defaults
    pricing.plans = [
      { name: '社区版', tagline: '个人开发者首选', price_cny: '¥0', price_usd: '$0', period: '永久免费', note: '开源（AGPL）', cta: '免费下载', popular: false, coming_soon: false, enabled: true, features_text: '' },
      { name: '专业版', tagline: '独立开发者/小团队', price_cny: '¥349', price_usd: '$49', period: '大版本永久', note: '', cta: '立即购买', popular: true, coming_soon: false, enabled: true, features_text: '' },
      { name: '企业版', tagline: '中小企业/团队', price_cny: '¥699', price_usd: '$99', period: '/年', note: '10 节点', cta: '购买企业版', popular: false, coming_soon: false, enabled: true, features_text: '' },
      { name: '旗舰版', tagline: '大型组织', price_cny: '¥2,099', price_usd: '$299', period: '/年', note: '', cta: '联系销售', popular: false, coming_soon: true, enabled: true, features_text: '' },
    ]
  }
})

const handleSave = async () => {
  saving.value = true
  try {
    await adminAPI.updatePricing(pricing)
    ElMessage.success('定价保存成功')
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.page-card { padding: 28px; }
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}
.card-header h3 { font-size: 18px; }
.plans-editor { display: flex; flex-direction: column; gap: 24px; }
.plan-edit { padding: 24px; }
.plan-edit-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.plan-edit-header h4 { font-size: 16px; }
.plan-form .form-row {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 16px;
}
</style>
