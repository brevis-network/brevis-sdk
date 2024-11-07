package prover

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/ethereum/go-ethereum/common"
)

func assignCustomInput(app sdk.AppCircuit, input *sdkproto.CustomInput) (sdk.AppCircuit, error) {
	makeErr := func(msg string, err ...error) (sdk.AppCircuit, error) {
		format := "cannot assign custom input: %s"
		if len(err) == 1 {
			return nil, fmt.Errorf(format+": %v", msg, err[0])
		}
		return nil, fmt.Errorf(format, msg)
	}

	// Support empty customInput
	jsonBytes := ""
	if input == nil {
		jsonBytes = "{}"
	} else {
		jsonBytes = input.JsonBytes
		if len(jsonBytes) == 0 {
			jsonBytes = "{}"
		}
	}

	// every custom input must be either at the top level or in a list that's at the top level of the struct
	var customInput map[string]interface{}
	err := json.Unmarshal([]byte(jsonBytes), &customInput)
	if err != nil {
		return makeErr("error reading custom input json", err)
	}

	vv := reflect.ValueOf(app)

	// deref until we get the actual value
	for vv.Kind() == reflect.Pointer {
		vv = vv.Elem()
	}

	if vv.Kind() != reflect.Struct {
		return makeErr("the concrete type of AppCircuit must be struct")
	}

	appStructRef := reflect.New(vv.Type())
	appStruct := appStructRef.Elem()
	structName := appStruct.Type().Name()

	for k, raw := range customInput {
		// capitalize the object key because all fields in an AppCircuit are exported
		k = strings.ToUpper(fmt.Sprintf("%c", k[0])) + k[1:]

		field := appStruct.FieldByName(k)
		if field == (reflect.Value{}) {
			return makeErr(fmt.Sprintf("received custom input field that does not exist in %s: %s", structName, k))
		}

		if isList(field) {
			values, ok := raw.([]interface{})
			if !ok {
				return makeErr(fmt.Sprintf("type mismatch: field %s is defined as list in %s but in decoded json it is %v", k, structName, raw))
			}
			parsedValues, err := parseCircuitValues(values)
			if err != nil {
				return makeErr(fmt.Sprintf("failed to parse json list %v into []CircuitVariable", values), err)
			}
			vs := reflect.ValueOf(parsedValues)
			// only slice fields require initialization before items can be set.
			if field.Kind() == reflect.Slice {
				field.Set(reflect.MakeSlice(field.Type(), vs.Len(), vs.Len()))
			}
			if err = setListItemsWithCheck(field, vs, structName); err != nil {
				return nil, err
			}
		} else { // `field` is json object
			parsedValue, err := parseCircuitValue(raw)
			if err != nil {
				return makeErr(fmt.Sprintf("failed to parse json object %v into CircuitVariable", raw))
			}
			v := reflect.ValueOf(parsedValue)
			field, v, err = convertType(field, v, structName)
			if err != nil {
				return makeErr(fmt.Sprintf("error assigning value for field %s", k), err)
			}
			field.Set(v)
		}
	}

	return appStructRef.Interface().(sdk.AppCircuit), nil
}

func setListItemsWithCheck(field reflect.Value, values reflect.Value, name string) error {
	if fl, vl := field.Len(), values.Len(); fl != vl {
		fmt.Printf("WARNING: inconsistent lengths: json has len %d but %s has len %d", fl, name, vl)
	}
	for i := 0; i < values.Len(); i++ {
		if i >= field.Len() {
			break
		}
		fi := field.Index(i)
		vi := values.Index(i)
		fi, vi, err := convertType(fi, vi, name)
		if err != nil {
			return err
		}
		fi.Set(vi)
	}
	return nil
}

func convertType(expect, actual reflect.Value, name string) (reflect.Value, reflect.Value, error) {
	et, at := expect.Type(), actual.Type()
	if at == et {
		return expect, actual, nil
	}
	switch et.Name() {
	case sdk.Uint248Type:
		actual = reflect.ValueOf(actual.Interface().(sdk.Uint248))
	case sdk.Uint521Type:
		actual = reflect.ValueOf(actual.Interface().(sdk.Uint521))
	case sdk.Int248Type:
		actual = reflect.ValueOf(actual.Interface().(sdk.Int248))
	case sdk.Bytes32Type:
		actual = reflect.ValueOf(actual.Interface().(sdk.Bytes32))
	case sdk.Uint32Type:
		actual = reflect.ValueOf(actual.Interface().(sdk.Uint32))
	case sdk.Uint64Type:
		actual = reflect.ValueOf(actual.Interface().(sdk.Uint64))
	default:
		return reflect.Value{}, reflect.Value{}, fmt.Errorf("mismatch types: json has %s but %s has %s", at, name, et)
	}
	return expect, actual.Convert(expect.Type()), nil
}

func isList(field reflect.Value) bool {
	return field.Kind() == reflect.Array || field.Kind() == reflect.Slice
}

func parseCircuitValues(values []interface{}) ([]interface{}, error) {
	res := make([]interface{}, len(values))
	var expectType *reflect.Type
	for i, value := range values {
		circuitVar, err := parseCircuitValue(value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %d-th list item %v: %v", i, value, err)
		}
		actualType := reflect.TypeOf(circuitVar)
		if expectType != nil && actualType != *expectType {
			return nil, fmt.Errorf("inconsistent types in %d-th list item %v", i, value)
		}
		expectType = &actualType
		res[i] = circuitVar
	}
	return res, nil
}

// parses the input json object into `sdk.CircuitVariable`
func parseCircuitValue(value interface{}) (interface{}, error) {
	val, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse value %v", value)
	}
	data, ok := val["data"]
	if !ok {
		return nil, fmt.Errorf("failed to parse value %v", value)
	}
	typ, ok := val["type"]
	if !ok {
		return nil, fmt.Errorf("failed to parse value %v", value)
	}

	switch typ {
	case sdk.Uint248Type:
		return sdk.ConstUint248(data), nil
	case sdk.Uint521Type:
		return sdk.ConstUint521(data), nil
	case sdk.Uint32Type:
		return sdk.ConstUint32(data), nil
	case sdk.Uint64Type:
		return sdk.ConstUint64(data), nil
	case sdk.Int248Type:
		// json.Unmarshal automatically removes "" (quotes) around numbers. we need to check again here
		str, ok := data.(string)
		if !ok {
			data = strconv.Itoa(data.(int))
		}
		b, ok := new(big.Int).SetString(str, 10)
		if !ok {
			return nil, fmt.Errorf("invalid Int248 encoding %s", data)
		}
		return sdk.ConstInt248(b), nil
	case sdk.Bytes32Type:
		bytes := common.FromHex(data.(string))
		return sdk.ConstBytes32(bytes), nil
	default:
		return nil, fmt.Errorf("unsupported circuit value type %s", typ)
	}
}
