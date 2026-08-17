require("../../../_virtual/_rolldown/runtime.js");
const require_style = require("../../../utils/dom/style.js");
const require_index = require("../../../hooks/use-namespace/index.js");
const require_index$1 = require("../../tooltip/index.js");
const require_popover = require("./popover.js");
let lodash_unified = require("lodash-unified");
let vue = require("vue");
let _vue_shared = require("@vue/shared");
//#region ../../packages/components/popover/src/popover.vue?vue&type=script&setup=true&lang.ts
var popover_vue_vue_type_script_setup_true_lang_default = /* @__PURE__ */ (0, vue.defineComponent)({
	name: "ElPopover",
	__name: "popover",
	props: require_popover.popoverProps,
	emits: require_popover.popoverEmits,
	setup(__props, { expose: __expose, emit: __emit }) {
		const props = __props;
		const emit = __emit;
		const passTooltipProps = (0, vue.computed)(() => {
			const tooltipProps = require_index$1.ElTooltip.props;
			return (0, lodash_unified.pick)(props, (0, _vue_shared.isArray)(tooltipProps) ? tooltipProps : Object.keys(tooltipProps));
		});
		const ns = require_index.useNamespace("popover");
		const tooltipRef = (0, vue.ref)();
		const popperRef = (0, vue.computed)(() => {
			return (0, vue.unref)(tooltipRef)?.popperRef;
		});
		const style = (0, vue.computed)(() => {
			return [{ width: require_style.addUnit(props.width) }, props.popperStyle];
		});
		const kls = (0, vue.computed)(() => {
			return [
				ns.b(),
				props.popperClass,
				{ [ns.m("plain")]: !!props.content }
			];
		});
		const gpuAcceleration = (0, vue.computed)(() => {
			return props.transition === `${ns.namespace.value}-fade-in-linear`;
		});
		const hide = () => {
			tooltipRef.value?.hide();
		};
		const beforeEnter = () => {
			emit("before-enter");
		};
		const beforeLeave = () => {
			emit("before-leave");
		};
		const afterEnter = () => {
			emit("after-enter");
		};
		const afterLeave = () => {
			emit("update:visible", false);
			emit("after-leave");
		};
		__expose({
			/** @description popper ref */
			popperRef,
			/** @description hide popover */
			hide
		});
		return (_ctx, _cache) => {
			return (0, vue.openBlock)(), (0, vue.createBlock)((0, vue.unref)(require_index$1.ElTooltip), (0, vue.mergeProps)({
				ref_key: "tooltipRef",
				ref: tooltipRef
			}, passTooltipProps.value, {
				"aria-label": __props.title,
				"popper-class": kls.value,
				"popper-style": style.value,
				"gpu-acceleration": gpuAcceleration.value,
				onBeforeShow: beforeEnter,
				onBeforeHide: beforeLeave,
				onShow: afterEnter,
				onHide: afterLeave
			}), {
				content: (0, vue.withCtx)(() => [__props.title ? ((0, vue.openBlock)(), (0, vue.createElementBlock)("div", {
					key: 0,
					class: (0, vue.normalizeClass)((0, vue.unref)(ns).e("title")),
					role: "title"
				}, (0, vue.toDisplayString)(__props.title), 3)) : (0, vue.createCommentVNode)("v-if", true), (0, vue.renderSlot)(_ctx.$slots, "default", { hide }, () => [(0, vue.createTextVNode)((0, vue.toDisplayString)(__props.content), 1)])]),
				default: (0, vue.withCtx)(() => [_ctx.$slots.reference ? (0, vue.renderSlot)(_ctx.$slots, "reference", { key: 0 }) : (0, vue.createCommentVNode)("v-if", true)]),
				_: 3
			}, 16, [
				"aria-label",
				"popper-class",
				"popper-style",
				"gpu-acceleration"
			]);
		};
	}
});
//#endregion
exports.default = popover_vue_vue_type_script_setup_true_lang_default;

//# sourceMappingURL=popover.vue_vue_type_script_setup_true_lang.js.map