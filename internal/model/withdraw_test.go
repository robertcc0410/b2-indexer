package model_test

// func TestValidateWithdrawColumn(t *testing.T) {
// 	var d model.Withdraw
// 	dc := model.Withdraw{}.Column()
//
// 	dFields := reflect.TypeOf(d)
// 	dcValues := reflect.ValueOf(dc)
//
// 	dJSONTags := []string{}
// 	for i := 0; i < dFields.NumField(); i++ {
// 		dField := dFields.Field(i)
// 		dJSONTag := dField.Tag.Get("json")
// 		dJSONTags = append(dJSONTags, dJSONTag)
// 	}
//
// 	for i := 0; i < dcValues.NumField(); i++ {
// 		dcValue := dcValues.Field(i).String()
// 		if !utils.StrInArray(dJSONTags, dcValue) {
// 			t.Fatalf("WithdrawColumn field %s not found in deposit %s", dcValue, dJSONTags)
// 		}
// 	}
// }
