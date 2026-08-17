import { EpPropFinalized, EpPropMergeType } from "../../../../utils/vue/props/types.js";
import { ClassValue } from "../../../../utils/typescript.js";
import _default from "./sizes.vue.js";
import * as _$vue from "vue";
import { ExtractPropTypes, ExtractPublicPropTypes, StyleValue } from "vue";

//#region ../../packages/components/pagination/src/components/sizes.d.ts
declare const paginationSizesProps: {
  readonly pageSize: {
    readonly type: _$vue.PropType<number>;
    readonly required: true;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
  readonly pageSizes: EpPropFinalized<(new (...args: any[]) => number[]) | (() => number[]) | (((new (...args: any[]) => number[]) | (() => number[])) | null)[], unknown, unknown, () => [10, 20, 30, 40, 50, 100], boolean>;
  readonly popperClass: EpPropFinalized<(new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue) | (((new (...args: any[]) => string | false | Record<string, any> | ClassValue[]) | (() => ClassValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly popperStyle: EpPropFinalized<(new (...args: any[]) => string | false | _$vue.CSSProperties | StyleValue[]) | (() => StyleValue) | (((new (...args: any[]) => string | false | _$vue.CSSProperties | StyleValue[]) | (() => StyleValue)) | null)[], unknown, unknown, undefined, boolean>;
  readonly disabled: BooleanConstructor;
  readonly teleported: BooleanConstructor;
  readonly size: {
    readonly type: _$vue.PropType<EpPropMergeType<StringConstructor, "" | "default" | "small" | "large", unknown>>;
    readonly required: false;
    readonly validator: ((val: unknown) => boolean) | undefined;
    __epPropKey: true;
  };
  readonly appendSizeTo: StringConstructor;
};
type PaginationSizesProps = ExtractPropTypes<typeof paginationSizesProps>;
type PaginationSizesPropsPublic = ExtractPublicPropTypes<typeof paginationSizesProps>;
type SizesInstance = InstanceType<typeof _default> & unknown;
//#endregion
export { PaginationSizesProps, PaginationSizesPropsPublic, SizesInstance, paginationSizesProps };