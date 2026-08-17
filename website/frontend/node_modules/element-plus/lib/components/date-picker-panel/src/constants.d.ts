import { UseNamespaceReturn } from "../../../hooks/use-namespace/index.js";
import { InjectionKey, SetupContext } from "vue";

//#region ../../packages/components/date-picker-panel/src/constants.d.ts
interface DatePickerContext {
  slots: SetupContext['slots'];
  pickerNs: UseNamespaceReturn;
}
declare const ROOT_PICKER_INJECTION_KEY: InjectionKey<DatePickerContext>;
//#endregion
export { ROOT_PICKER_INJECTION_KEY };