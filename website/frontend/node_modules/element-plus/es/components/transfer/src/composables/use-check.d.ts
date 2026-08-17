import { FixedSizeListInstance } from "../../../virtual-list/src/components/fixed-size-list.js";
import { CheckboxValueType } from "../../../checkbox/src/checkbox.js";
import { CheckboxGroupInstance } from "../../../checkbox/src/checkbox-group.js";
import { TransferDataItem } from "../transfer.js";
import { TransferPanelEmits, TransferPanelProps, TransferPanelState } from "../transfer-panel.js";
import * as _$vue from "vue";
import { SetupContext } from "vue";

//#region ../../packages/components/transfer/src/composables/use-check.d.ts
declare const useCheck: <T extends TransferDataItem = TransferDataItem>(props: Required<Pick<TransferPanelProps<T>, "data" | "format" | "defaultChecked" | "props" | "virtualScroll">> & {
  filterMethod: TransferPanelProps<T>["filterMethod"];
}, panelState: TransferPanelState, emit: SetupContext<TransferPanelEmits>["emit"]) => {
  filteredData: _$vue.ComputedRef<T[]>;
  checkableData: _$vue.ComputedRef<T[]>;
  checkedSummary: _$vue.ComputedRef<string>;
  virtualListRef: _$vue.Ref<FixedSizeListInstance | undefined, FixedSizeListInstance | undefined>;
  isIndeterminate: _$vue.ComputedRef<boolean>;
  checkboxGroupRef: _$vue.Ref<CheckboxGroupInstance | undefined, CheckboxGroupInstance | undefined>;
  virtualListHeight: _$vue.ShallowRef<number>;
  updateAllChecked: () => void;
  handleAllCheckedChange: (value: CheckboxValueType) => void;
};
//#endregion
export { useCheck };