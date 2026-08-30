<template>
  <span>{{ displayValue }}</span>
</template>

<script setup lang="ts">
import { toRef, watch } from 'vue'
import { useCountUp } from '../composables/useCountUp'

const props = defineProps<{
  value: number
  duration?: number
}>()

const target = toRef(props, 'value')
const displayValue = useCountUp(target, props.duration ?? 800)
</script>
