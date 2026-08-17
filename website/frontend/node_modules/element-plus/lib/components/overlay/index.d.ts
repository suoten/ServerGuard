import { EpPropFinalized, EpPropMergeType } from "../../utils/vue/props/types.js";
import { ClassValue } from "../../utils/typescript.js";
import { OverlayEmits, OverlayProps, OverlayPropsPublic, overlayEmits, overlayProps } from "./src/overlay.js";
import * as _$vue from "vue";
import * as _$csstype from "csstype";

//#region ../../packages/components/overlay/index.d.ts
declare const ElOverlay: _$vue.DefineComponent<_$vue.ExtractPropTypes<{
  readonly mask: EpPropFinalized<BooleanConstructor, unknown, unknown, true, boolean>;
  readonly customMaskEvent: BooleanConstructor;
  readonly overlayClass: EpPropFinalized<(new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue) | (((new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly zIndex: {
    readonly type: _$vue.PropType<EpPropMergeType<(new (...args: any[]) => string | number) | (() => _$csstype.Property.ZIndex | undefined) | (((new (...args: any[]) => string | number) | (() => _$csstype.Property.ZIndex | undefined)) | null)[], unknown, unknown>>;
    readonly required: false;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
}>, () => _$vue.VNode<_$vue.RendererNode, _$vue.RendererElement, {
  [key: string]: any;
}>, {}, {}, {}, _$vue.ComponentOptionsMixin, _$vue.ComponentOptionsMixin, {
  click: (evt: MouseEvent) => boolean;
}, string, _$vue.PublicProps, Readonly<_$vue.ExtractPropTypes<{
  readonly mask: EpPropFinalized<BooleanConstructor, unknown, unknown, true, boolean>;
  readonly customMaskEvent: BooleanConstructor;
  readonly overlayClass: EpPropFinalized<(new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue) | (((new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly zIndex: {
    readonly type: _$vue.PropType<EpPropMergeType<(new (...args: any[]) => string | number) | (() => _$csstype.Property.ZIndex | undefined) | (((new (...args: any[]) => string | number) | (() => _$csstype.Property.ZIndex | undefined)) | null)[], unknown, unknown>>;
    readonly required: false;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
}>> & Readonly<{
  onClick?: ((evt: MouseEvent) => any) | undefined;
}>, {
  readonly mask: EpPropMergeType<BooleanConstructor, unknown, unknown>;
  readonly overlayClass: ClassValue;
  readonly customMaskEvent: boolean;
}, {}, {}, {}, string, _$vue.ComponentProvideOptions, true, {}, any>;
//#endregion
export { ElOverlay, ElOverlay as default, OverlayEmits, OverlayProps, OverlayPropsPublic, overlayEmits, overlayProps };