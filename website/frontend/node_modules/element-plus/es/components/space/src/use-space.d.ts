import { ClassValue } from "../../../utils/typescript.js";
import { SpaceProps } from "./space.js";
import * as _$vue from "vue";
import { StyleValue } from "vue";

//#region ../../packages/components/space/src/use-space.d.ts
declare function useSpace(props: SpaceProps): {
  classes: _$vue.ComputedRef<(string | false | Record<string, any> | ClassValue[] | null)[]>;
  containerStyle: _$vue.ComputedRef<StyleValue>;
  itemStyle: _$vue.ComputedRef<StyleValue>;
};
//#endregion
export { useSpace };