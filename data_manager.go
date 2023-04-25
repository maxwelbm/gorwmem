package gorwmem

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// DataType Type of the data.
type DataType int

// Enum of data types.
const (
	UINT DataType = iota
	INT
	BYTE
	STRING
	FLOAT
	ARRAY
)

// String representation of data types.
var dataTypes = [...]string{
	"uint",
	"int",
	"byte",
	"string",
	"float",
}

// String Get the string value from enum value.
func (dataType DataType) String() string {
	return dataTypes[dataType]
}

// DataException Exception type of DataManager.
type DataException error

// Data This type warp the read and write values.
type Data struct {
	Value    interface{} // Any type value.
	DataType DataType    // Unwarp value.
}

// DataManager This type is the Facade for read and write.
type DataManager struct {
	ProcessName string          //Name of the process.
	process     *processHandler //This handles the low level facade.
	IsOpen      bool            //True if we are in process.
}

// GetDataManager Constructor of DataManager
// Param   (processName)  : The name of process to handle.
// Returns (*dataManager) : A dataManager object.
func GetDataManager(processName string) *DataManager {
	_err := error(nil)
	dm := &DataManager{}
	dm.ProcessName = processName

	dm.process, _err = ProcessHandler(processName)
	if _err != nil {
		_ = fmt.Errorf("Error in processHandler: %s\n", _err)
		return dm
	}

	_err = dm.process.Open()
	if _err != nil {
		_ = fmt.Errorf("Error in processHandler Open: %s\n", _err)
		return dm
	} else {
		dm.IsOpen = true
	}

	return dm
}

// Read
// Facade to Read methods.
// Public function of (data_manager) package.
// Param   (address)  : The process memory address in hexadecimal. EX: (0X0057F0F0).
// Param   (size)     : Size array
// Param   (dataType) : The type of data that want to retrieve.
// Returns (data)     : The data from memory. If low level facade fails, this will be nil.
// Errors  (err)	  : This will be not nil if handle is not opened or the type is invalid.
func (dm *DataManager) Read(address, size uint, dataType DataType) (data Data, err DataException) {
	_err := error(nil)

	if !dm.IsOpen {
		err = errors.New("process is not open")
		return
	}

	switch dataType {
	case UINT:
		data, _err = dm.readUint(address)
	case INT:
		data, _err = dm.readInt(address)
	case BYTE:
		data, _err = dm.readByte(address)
	case STRING:
		data, _err = dm.readString(address)
	case ARRAY:
		data, _err = dm.readArray(address, size)
	default:
		err = errors.New("invalid data type")
	}

	if _err != nil {
		_ = fmt.Errorf("Error in processHandler Read: %s\n", _err)
	}

	return
}

// GetModuleFromName Specific method for read a byte.
func (dm *DataManager) GetModuleFromName(module string) (address uintptr, err ProcessException) {
	return dm.process.GetModuleFromName(module)
}

// Specific method for read a byte.
func (dm *DataManager) readByte(address uint) (data Data, err ProcessException) {
	data.DataType = BYTE

	_data, err := dm.process.ReadBytes(address, 1)
	data.Value = _data[0]
	return
}

// readString Specific method for read a String.
func (dm *DataManager) readString(address uint) (data Data, err ProcessException) {
	data.DataType = STRING

	wordBytes := make([]byte, 0)
	_address := address

	for {
		_data, _err := dm.readByte(_address)
		if _err != nil {
			_ = fmt.Errorf("Error in DataManager readByte: %s\n", _err)
			break
		}

		value := _data.Value.(byte)

		if value == 0 {
			break
		}

		_address += 0x01
		wordBytes = append(wordBytes, value)
	}

	data.Value = string(wordBytes[:])

	return
}

// readByteArray Specific func for read a slice of byte.
func (dm *DataManager) readByteArray(address, size uint) (data Data, err ProcessException) {
	data.DataType = BYTE

	_data, err := dm.process.ReadBytes(address, size)
	data.Value = _data[0]
	return
}

// readArray specific func for read array memory
func (dm *DataManager) readArray(address, size uint) (data Data, err ProcessException) {
	data.DataType = ARRAY

	byteSlice := make([]byte, size)
	_address := address

	for i := 0; i < int(size); i++ {
		_data, _err := dm.readByteArray(_address, size)
		if _err != nil {
			err = fmt.Errorf("Error in DataManager readByte: %s\n", _err)
			return
		}

		value := _data.Value.(byte)

		byteSlice[i] = value
		_address += 0x01
	}

	data.Value = byteSlice

	return
}

// readInt Specific method for read an int.
func (dm *DataManager) readInt(address uint) (data Data, err ProcessException) {
	data.DataType = INT

	_data, err := dm.process.ReadBytes(address, 4)
	data.Value = int(binary.LittleEndian.Uint32(_data))
	return
}

// readUint Specific method for read an uint.
func (dm *DataManager) readUint(address uint) (data Data, err ProcessException) {
	data.DataType = UINT

	_data, err := dm.process.ReadBytes(address, 4)
	data.Value = binary.LittleEndian.Uint32(_data)
	return
}

// Write Facade to Write methods.
// Public function of (data_manager) package.
// Param   (address) : The process memory address in hexadecimal. EX: (0X0057F0F0).
// Param   (data)    : The data to write.
// Errors  (err)	 : This will be not nil if handle is not opened or the type is invalid.
func (dm *DataManager) Write(address uint, data Data) (err DataException) {
	_err := error(nil)

	if !dm.IsOpen {
		err = errors.New("process is not open")
		return
	}

	switch data.DataType {
	case UINT:
		_err = dm.writeUint(address, uint(data.Value.(int)))
	case INT:
		_err = dm.writeInt(address, data.Value.(int))
	case BYTE:
		_err = dm.writeByte(address, byte(data.Value.(int)))
	case STRING:
		_err = dm.writeString(address, data.Value.(string))
	case FLOAT:
		_err = dm.writeFloat(address, data.Value.(float32))
	default:
		err = errors.New("invalid data type")
	}

	if _err != nil {
		_ = fmt.Errorf("Error in processHandler Write: %s\n", _err)
	}

	return
}

// Specific method for write a byte.
func (dm *DataManager) writeByte(address uint, b byte) (err ProcessException) {
	data := []byte{b}

	err = dm.process.WriteBytes(address, data)

	return
}

// Specific method for write a string.
func (dm *DataManager) writeString(address uint, str string) (err ProcessException) {
	data := []byte(str)

	err = dm.process.WriteBytes(address, data)

	return
}

// Specific method for write an int.
func (dm *DataManager) writeInt(address uint, i int) (err ProcessException) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(i))

	err = dm.process.WriteBytes(address, data)

	return
}

// Specific method for write an uint.
func (dm *DataManager) writeUint(address uint, u uint) (err ProcessException) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(u))

	err = dm.process.WriteBytes(address, data)

	return
}

func (dm *DataManager) writeFloat(address uint, f float32) (err ProcessException) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[:], math.Float32bits(f))
	err = dm.process.WriteBytes(address, data)

	return
}
