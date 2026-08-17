Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
require("../../../_virtual/_rolldown/runtime.js");
const require_types = require("../../../utils/types.js");
const require_runtime$1 = require("../../../utils/vue/props/runtime.js");
const require_arrow = require("../../popper/src/arrow.js");
const require_content = require("../../tooltip/src/content.js");
const require_trigger = require("../../tooltip/src/trigger.js");
const require_tooltip = require("../../tooltip/src/tooltip.js");
const require_dropdown = require("../../dropdown/src/dropdown.js");
let lodash_unified = require("lodash-unified");
//#region ../../packages/components/popover/src/popover.ts
/**
* @deprecated Removed after 3.0.0, Use `PopoverProps` instead.
*/
const popoverProps = require_runtime$1.buildProps({
	...(0, lodash_unified.omit)(require_tooltip.useTooltipProps, [
		"ariaLabel",
		"gpuAcceleration",
		"rawContent"
	]),
	/**
	* @description popover placement
	*/
	placement: require_dropdown.dropdownProps.placement,
	/**
	* @description [tabindex](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/tabindex) of Popover
	*/
	tabindex: require_dropdown.dropdownProps.tabindex,
	/**
	* @description Tooltip theme, built-in theme: `dark` / `light`
	*/
	effect: {
		...require_tooltip.useTooltipProps.effect,
		default: "light"
	},
	/**
	* @description popover title
	*/
	title: String,
	/**
	* @description popover width
	*/
	width: {
		type: [String, Number],
		default: 150
	},
	/**
	* @description popover offset
	*/
	offset: {
		...require_tooltip.useTooltipProps.offset,
		default: void 0
	},
	/**
	* @description when popover inactive and `persistent` is `false` , popover will be destroyed
	*/
	persistent: {
		...require_tooltip.useTooltipProps.persistent,
		default: true
	}
});
const popoverEmits = {
	"update:visible": (value) => require_types.isBoolean(value),
	"before-enter": () => true,
	"before-leave": () => true,
	"after-enter": () => true,
	"after-leave": () => true
};
/**
* @description default values for PopoverProps
*/
const popoverPropsDefaults = {
	...(0, lodash_unified.omit)(require_content.useTooltipContentPropsDefaults, ["gpuAcceleration"]),
	...require_trigger.useTooltipTriggerPropsDefaults,
	...require_arrow.popperArrowPropsDefaults,
	title: void 0,
	tabindex: 0,
	effect: "light",
	width: 150,
	offset: void 0,
	showArrow: true,
	persistent: true
};
//#endregion
exports.popoverEmits = popoverEmits;
exports.popoverProps = popoverProps;
exports.popoverPropsDefaults = popoverPropsDefaults;

//# sourceMappingURL=popover.js.map