import { IconPropType } from "../../../utils/vue/icon.js";
import { EpPropFinalized, EpPropMergeType } from "../../../utils/vue/props/types.js";
import { ComponentSize } from "../../../constants/size.js";
import { ClassValue } from "../../../utils/typescript.js";
import { PopperEffect } from "../../popper/src/popper.js";
import _default from "./time-select.vue.js";
import { UseEmptyValuesProps } from "../../../hooks/use-empty-values/index.js";
import * as _$vue from "vue";
import { Component, ExtractPublicPropTypes, StyleValue } from "vue";

//#region ../../packages/components/time-select/src/time-select.d.ts
interface TimeSelectProps extends UseEmptyValuesProps {
  /**
   * @description set format of time
   */
  format?: string;
  /**
   * @description binding value
   */
  modelValue?: string | null;
  /**
   * @description whether TimeSelect is disabled
   */
  disabled?: boolean;
  /**
   * @description whether the input is editable
   */
  editable?: boolean;
  /**
   * @description Tooltip theme, built-in theme: `dark` / `light`
   */
  effect?: PopperEffect;
  /**
   * @description whether to show clear button
   */
  clearable?: boolean;
  /**
   * @description size of Input
   */
  size?: ComponentSize;
  /**
   * @description placeholder in non-range mode
   */
  placeholder?: string;
  /**
   * @description start time
   */
  start?: string;
  /**
   * @description end time
   */
  end?: string;
  /**
   * @description time step
   */
  step?: string;
  /**
   * @description minimum time, any time before this time will be disabled
   */
  minTime?: string | null;
  /**
   * @description maximum time, any time after this time will be disabled
   */
  maxTime?: string | null;
  /**
   * @description whether `end` is included in options
   */
  includeEndTime?: boolean;
  /**
   * @description same as `name` in native input
   */
  name?: string;
  /**
   * @description custom prefix icon component
   */
  prefixIcon?: IconPropType;
  /**
   * @description custom clear icon component
   */
  clearIcon?: IconPropType;
  /**
   * @description custom class name for TimeSelect's dropdown
   */
  popperClass?: ClassValue;
  /**
   * @description custom style for TimeSelect's dropdown
   */
  popperStyle?: StyleValue;
}
declare const DEFAULT_START = "09:00";
declare const DEFAULT_END = "18:00";
declare const DEFAULT_STEP = "00:30";
/**
 * @deprecated Removed after 3.0.0, Use `TimeSelectProps` instead.
 */
declare const timeSelectProps: {
  readonly emptyValues: ArrayConstructor;
  readonly valueOnClear: EpPropFinalized<(new (...args: any[]) => string | number | boolean | Function) | (() => string | number | boolean | Function | null) | (((new (...args: any[]) => string | number | boolean | Function) | (() => string | number | boolean | Function | null)) | null)[], unknown, unknown, undefined, boolean>;
  readonly format: EpPropFinalized<StringConstructor, unknown, unknown, "HH:mm", boolean>;
  readonly modelValue: {
    readonly type: _$vue.PropType<EpPropMergeType<(new (...args: any[]) => string) | (() => string | null) | (((new (...args: any[]) => string) | (() => string | null)) | null)[], unknown, unknown>>;
    readonly required: false;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
  readonly disabled: EpPropFinalized<BooleanConstructor, unknown, unknown, undefined, boolean>;
  readonly editable: EpPropFinalized<BooleanConstructor, unknown, unknown, true, boolean>;
  readonly effect: EpPropFinalized<(new (...args: any[]) => string) | (() => PopperEffect) | (((new (...args: any[]) => string) | (() => PopperEffect)) | null)[], unknown, unknown, "light", boolean>;
  readonly clearable: EpPropFinalized<BooleanConstructor, unknown, unknown, true, boolean>;
  readonly size: {
    readonly type: _$vue.PropType<EpPropMergeType<StringConstructor, "" | "default" | "small" | "large", never>>;
    readonly required: false;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
  readonly placeholder: StringConstructor;
  readonly start: EpPropFinalized<StringConstructor, unknown, unknown, "09:00", boolean>;
  readonly end: EpPropFinalized<StringConstructor, unknown, unknown, "18:00", boolean>;
  readonly step: EpPropFinalized<StringConstructor, unknown, unknown, "00:30", boolean>;
  readonly minTime: {
    readonly type: _$vue.PropType<EpPropMergeType<(new (...args: any[]) => string) | (() => string | null) | (((new (...args: any[]) => string) | (() => string | null)) | null)[], unknown, unknown>>;
    readonly required: false;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
  readonly maxTime: {
    readonly type: _$vue.PropType<EpPropMergeType<(new (...args: any[]) => string) | (() => string | null) | (((new (...args: any[]) => string) | (() => string | null)) | null)[], unknown, unknown>>;
    readonly required: false;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
  readonly includeEndTime: BooleanConstructor;
  readonly name: StringConstructor;
  readonly prefixIcon: EpPropFinalized<(new (...args: any[]) => (string | Component) & {}) | (() => string | Component) | (((new (...args: any[]) => (string | Component) & {}) | (() => string | Component)) | null)[], unknown, unknown, () => _$vue.DefineComponent<{}, void, {}, {}, {}, _$vue.ComponentOptionsMixin, _$vue.ComponentOptionsMixin, {}, string, _$vue.PublicProps, Readonly<{}>, {}, {}, {}, {}, string, _$vue.ComponentProvideOptions, true, {}, any>, boolean>;
  readonly clearIcon: EpPropFinalized<(new (...args: any[]) => (string | Component) & {}) | (() => string | Component) | (((new (...args: any[]) => (string | Component) & {}) | (() => string | Component)) | null)[], unknown, unknown, () => _$vue.DefineComponent<{}, void, {}, {}, {}, _$vue.ComponentOptionsMixin, _$vue.ComponentOptionsMixin, {}, string, _$vue.PublicProps, Readonly<{}>, {}, {}, {}, {}, string, _$vue.ComponentProvideOptions, true, {}, any>, boolean>;
  readonly popperClass: EpPropFinalized<(new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue) | (((new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue)) | null)[], unknown, unknown, "", boolean>;
  readonly popperStyle: EpPropFinalized<(new (...args: any[]) => string | false | _$vue.CSSProperties | StyleValue[]) | (() => StyleValue) | (((new (...args: any[]) => string | false | _$vue.CSSProperties | StyleValue[]) | (() => StyleValue)) | null)[], unknown, unknown, undefined, boolean>;
};
/**
 * @deprecated Removed after 3.0.0, Use `TimeSelectProps` instead.
 */
type TimeSelectPropsPublic = ExtractPublicPropTypes<typeof timeSelectProps>;
type TimeSelectInstance = InstanceType<typeof _default> & unknown;
//#endregion
export { DEFAULT_END, DEFAULT_START, DEFAULT_STEP, TimeSelectInstance, TimeSelectProps, TimeSelectPropsPublic, timeSelectProps };