import { isBoolean } from "../../../utils/types.mjs";
import { buildProps } from "../../../utils/vue/props/runtime.mjs";
import { popperArrowPropsDefaults } from "../../popper/src/arrow.mjs";
import { useTooltipContentPropsDefaults } from "../../tooltip/src/content.mjs";
import { useTooltipTriggerPropsDefaults } from "../../tooltip/src/trigger.mjs";
import { useTooltipProps } from "../../tooltip/src/tooltip.mjs";
import { dropdownProps } from "../../dropdown/src/dropdown.mjs";
import { omit } from "lodash-unified";
//#region ../../packages/components/popover/src/popover.ts
/**
* @deprecated Removed after 3.0.0, Use `PopoverProps` instead.
*/
const popoverProps = buildProps({
	...omit(useTooltipProps, [
		"ariaLabel",
		"gpuAcceleration",
		"rawContent"
	]),
	/**
	* @description popover placement
	*/
	placement: dropdownProps.placement,
	/**
	* @description [tabindex](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/tabindex) of Popover
	*/
	tabindex: dropdownProps.tabindex,
	/**
	* @description Tooltip theme, built-in theme: `dark` / `light`
	*/
	effect: {
		...useTooltipProps.effect,
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
		...useTooltipProps.offset,
		default: void 0
	},
	/**
	* @description when popover inactive and `persistent` is `false` , popover will be destroyed
	*/
	persistent: {
		...useTooltipProps.persistent,
		default: true
	}
});
const popoverEmits = {
	"update:visible": (value) => isBoolean(value),
	"before-enter": () => true,
	"before-leave": () => true,
	"after-enter": () => true,
	"after-leave": () => true
};
/**
* @description default values for PopoverProps
*/
const popoverPropsDefaults = {
	...omit(useTooltipContentPropsDefaults, ["gpuAcceleration"]),
	...useTooltipTriggerPropsDefaults,
	...popperArrowPropsDefaults,
	title: void 0,
	tabindex: 0,
	effect: "light",
	width: 150,
	offset: void 0,
	showArrow: true,
	persistent: true
};
//#endregion
export { popoverEmits, popoverProps, popoverPropsDefaults };

//# sourceMappingURL=popover.mjs.map