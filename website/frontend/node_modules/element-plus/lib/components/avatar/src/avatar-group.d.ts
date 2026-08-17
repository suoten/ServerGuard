import { EpPropFinalized } from "../../../utils/vue/props/types.js";
import { ClassValue } from "../../../utils/typescript.js";
import { PopperEffect } from "../../popper/src/popper.js";
import { Placement } from "../../popper/index.js";
import * as _$vue from "vue";
import * as _$vue_jsx_runtime0 from "vue/jsx-runtime";

//#region ../../packages/components/avatar/src/avatar-group.d.ts
declare const _default: _$vue.DefineComponent<_$vue.ExtractPropTypes<{
  readonly size: {
    readonly type: _$vue.PropType<number | "" | "default" | "small" | "large" | undefined>;
    readonly values: readonly ["", "default", "small", "large"];
    readonly validator: (val: unknown) => val is number;
  };
  readonly shape: {
    readonly type: _$vue.PropType<"square" | "circle" | undefined>;
    readonly values: readonly ["circle", "square"];
  };
  readonly collapseAvatars: BooleanConstructor;
  readonly collapseAvatarsTooltip: BooleanConstructor;
  readonly maxCollapseAvatars: {
    readonly type: NumberConstructor;
    readonly default: 1;
  };
  readonly effect: {
    readonly type: _$vue.PropType<PopperEffect>;
    readonly default: "light";
  };
  readonly placement: {
    readonly type: _$vue.PropType<Placement>;
    readonly values: Placement[];
    readonly default: "top";
  };
  readonly popperClass: EpPropFinalized<(new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue) | (((new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly popperStyle: EpPropFinalized<(new (...args: any[]) => string | false | _$vue.CSSProperties | _$vue.StyleValue[]) | (() => _$vue.StyleValue) | (((new (...args: any[]) => string | false | _$vue.CSSProperties | _$vue.StyleValue[]) | (() => _$vue.StyleValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly collapseClass: {
    readonly type: _$vue.PropType<ClassValue>;
    readonly default: undefined;
  };
  readonly collapseStyle: {
    readonly type: _$vue.PropType<_$vue.StyleValue>;
    readonly default: undefined;
  };
}>, () => _$vue_jsx_runtime0.JSX.Element, {}, {}, {}, _$vue.ComponentOptionsMixin, _$vue.ComponentOptionsMixin, {}, string, _$vue.PublicProps, Readonly<_$vue.ExtractPropTypes<{
  readonly size: {
    readonly type: _$vue.PropType<number | "" | "default" | "small" | "large" | undefined>;
    readonly values: readonly ["", "default", "small", "large"];
    readonly validator: (val: unknown) => val is number;
  };
  readonly shape: {
    readonly type: _$vue.PropType<"square" | "circle" | undefined>;
    readonly values: readonly ["circle", "square"];
  };
  readonly collapseAvatars: BooleanConstructor;
  readonly collapseAvatarsTooltip: BooleanConstructor;
  readonly maxCollapseAvatars: {
    readonly type: NumberConstructor;
    readonly default: 1;
  };
  readonly effect: {
    readonly type: _$vue.PropType<PopperEffect>;
    readonly default: "light";
  };
  readonly placement: {
    readonly type: _$vue.PropType<Placement>;
    readonly values: Placement[];
    readonly default: "top";
  };
  readonly popperClass: EpPropFinalized<(new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue) | (((new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly popperStyle: EpPropFinalized<(new (...args: any[]) => string | false | _$vue.CSSProperties | _$vue.StyleValue[]) | (() => _$vue.StyleValue) | (((new (...args: any[]) => string | false | _$vue.CSSProperties | _$vue.StyleValue[]) | (() => _$vue.StyleValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly collapseClass: {
    readonly type: _$vue.PropType<ClassValue>;
    readonly default: undefined;
  };
  readonly collapseStyle: {
    readonly type: _$vue.PropType<_$vue.StyleValue>;
    readonly default: undefined;
  };
}>> & Readonly<{}>, {
  readonly effect: PopperEffect;
  readonly popperClass: ClassValue;
  readonly popperStyle: _$vue.StyleValue;
  readonly placement: Placement;
  readonly collapseAvatars: boolean;
  readonly collapseAvatarsTooltip: boolean;
  readonly maxCollapseAvatars: number;
  readonly collapseClass: ClassValue;
  readonly collapseStyle: _$vue.StyleValue;
}, {}, {}, {}, string, _$vue.ComponentProvideOptions, true, {}, any>;
//#endregion
export { _default as default };