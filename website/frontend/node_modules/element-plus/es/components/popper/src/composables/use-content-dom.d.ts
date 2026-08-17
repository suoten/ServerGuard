import { ClassValue } from "../../../../utils/typescript.js";
import { PopperContentProps } from "../content.js";
import { UsePopperReturn } from "../../../../hooks/use-popper/index.js";
import { UsePopperContentReturn } from "./use-content.js";
import * as _$vue from "vue";
import { CSSProperties, StyleValue } from "vue";

//#region ../../packages/components/popper/src/composables/use-content-dom.d.ts
declare const usePopperContentDOM: (props: PopperContentProps, {
  attributes,
  styles,
  role
}: Pick<UsePopperReturn, "attributes" | "styles"> & Pick<UsePopperContentReturn, "role">) => {
  ariaModal: _$vue.ComputedRef<string | undefined>;
  arrowStyle: _$vue.ComputedRef<CSSProperties>;
  contentAttrs: _$vue.ComputedRef<{
    [key: string]: string | boolean;
  }>;
  contentClass: _$vue.ComputedRef<ClassValue[]>;
  contentStyle: _$vue.ComputedRef<StyleValue[]>;
  contentZIndex: _$vue.Ref<number, number>;
  updateZIndex: () => void;
};
type UsePopperContentDOMReturn = ReturnType<typeof usePopperContentDOM>;
//#endregion
export { UsePopperContentDOMReturn, usePopperContentDOM };