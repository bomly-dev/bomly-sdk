// Package deepcopytest checks that a deep copy shares no mutable memory with
// its source. It is test support: Fill populates every exported field of a
// value so a Clone that forgets one is exercised, and Aliases walks a source
// and its copy in lockstep -- unexported fields included -- reporting every
// pointer, map and slice backing array the two still share.
//
// It is reflection-based on purpose and lives outside the production path:
// the Clone methods it checks are hand-written because a reflective copier is
// slow on the hot path and cannot preserve a graph's indexes, and a check
// that read the same field list as the code under test would agree with it by
// construction.
package deepcopytest

import (
	"fmt"
	"reflect"
	"strconv"
)

// maxDepth bounds Fill on recursive types, so a self-referencing struct
// terminates with a populated prefix instead of overflowing the stack.
const maxDepth = 6

// Fill populates every exported field reachable from ptr with a non-zero
// value: two elements per slice and map, a fresh allocation per pointer, a
// distinct string per position, and a nested JSON-shaped map for every
// empty-interface field. Unexported fields and non-empty interfaces are left
// for the caller to set through the type's own constructor.
func Fill(ptr any) {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		panic("deepcopytest.Fill: want a non-nil pointer")
	}
	counter := 0
	fill(v.Elem(), 0, &counter)
}

func fill(v reflect.Value, depth int, counter *int) {
	if depth > maxDepth || !v.CanSet() {
		return
	}
	*counter++
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(*counter%100 + 1))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(uint64(*counter%100 + 1))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(*counter) + 0.5)
	case reflect.String:
		v.SetString("v" + strconv.Itoa(*counter))
	case reflect.Pointer:
		elem := reflect.New(v.Type().Elem())
		fill(elem.Elem(), depth+1, counter)
		v.Set(elem)
	case reflect.Slice:
		slice := reflect.MakeSlice(v.Type(), 2, 2)
		for i := range 2 {
			fill(slice.Index(i), depth+1, counter)
		}
		v.Set(slice)
	case reflect.Array:
		for i := range v.Len() {
			fill(v.Index(i), depth+1, counter)
		}
	case reflect.Map:
		m := reflect.MakeMapWithSize(v.Type(), 2)
		for range 2 {
			key := reflect.New(v.Type().Key()).Elem()
			fill(key, depth+1, counter)
			val := reflect.New(v.Type().Elem()).Elem()
			fill(val, depth+1, counter)
			m.SetMapIndex(key, val)
		}
		v.Set(m)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i), depth+1, counter)
			}
		}
	case reflect.Interface:
		if v.NumMethod() == 0 {
			v.Set(reflect.ValueOf(map[string]any{
				"list":   []any{"v" + strconv.Itoa(*counter), map[string]any{"leaf": true}},
				"nested": map[string]any{"value": float64(*counter)},
			}))
		}
	}
}

// Aliases reports every place where b, a deep copy of a, still shares mutable
// memory with it: the same non-nil pointer, the same map, or a slice whose
// backing array starts at the same address. Unexported fields are walked too,
// since a copy that shares a private index is as broken as one that shares a
// public field. Each entry names the path from the root.
func Aliases(a, b any) []string {
	var out []string
	walk(reflect.ValueOf(a), reflect.ValueOf(b), "$", map[visit]bool{}, &out)
	return out
}

type visit struct {
	a, b uintptr
	typ  reflect.Type
}

func walk(a, b reflect.Value, path string, seen map[visit]bool, out *[]string) {
	if !a.IsValid() || !b.IsValid() || a.Type() != b.Type() {
		return
	}
	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return
		}
		if a.Pointer() == b.Pointer() {
			*out = append(*out, path+": shared pointer")
			return
		}
		key := visit{a.Pointer(), b.Pointer(), a.Type()}
		if seen[key] {
			return
		}
		seen[key] = true
		walk(a.Elem(), b.Elem(), path, seen, out)
	case reflect.Map:
		if a.IsNil() || b.IsNil() {
			return
		}
		if a.Pointer() == b.Pointer() {
			*out = append(*out, path+": shared map")
			return
		}
		iter := a.MapRange()
		for iter.Next() {
			other := b.MapIndex(iter.Key())
			if other.IsValid() {
				walk(iter.Value(), other, fmt.Sprintf("%s[%v]", path, iter.Key()), seen, out)
			}
		}
	case reflect.Slice:
		if a.Cap() == 0 || b.Cap() == 0 {
			return
		}
		if a.Pointer() == b.Pointer() {
			*out = append(*out, path+": shared slice backing array")
			return
		}
		for i := range min(a.Len(), b.Len()) {
			walk(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", path, i), seen, out)
		}
	case reflect.Array:
		for i := range a.Len() {
			walk(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", path, i), seen, out)
		}
	case reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return
		}
		walk(a.Elem(), b.Elem(), path, seen, out)
	case reflect.Struct:
		for i := range a.NumField() {
			walk(a.Field(i), b.Field(i), path+"."+a.Type().Field(i).Name, seen, out)
		}
	}
}
