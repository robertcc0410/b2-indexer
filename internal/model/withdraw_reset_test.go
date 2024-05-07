package model_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/pkg/utils"
)

func TestValidateWithdrawResetColumn(t *testing.T) {
	var d model.WithdrawReset
	dc := model.WithdrawReset{}.Column()

	dFields := reflect.TypeOf(d)
	dcValues := reflect.ValueOf(dc)

	dJSONTags := []string{}
	for i := 0; i < dFields.NumField(); i++ {
		dField := dFields.Field(i)
		dJSONTag := dField.Tag.Get("json")
		dJSONTags = append(dJSONTags, dJSONTag)
	}

	for i := 0; i < dcValues.NumField(); i++ {
		dcValue := dcValues.Field(i).String()
		if !utils.StrInArray(dJSONTags, dcValue) {
			fmt.Println(dJSONTags, dcValue)
			t.Fatalf("WithdrawResetColumn field %s not found %s", dcValue, dJSONTags)
		}
	}
}
