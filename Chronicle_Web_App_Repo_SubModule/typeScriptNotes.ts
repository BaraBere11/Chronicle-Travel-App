// Install ts-node and typscript globally:
// npm install -g typescript ts-node

// Run script:
// npm ts-node typeScriptNotes.ts

// Variables and Data Types:
let variable = "hello"
variable = "hi"

let age = 18

//age = "eighteen"

let ageWithType: number = 22;

ageWithType = 18

//ageWithType = "jesadsda"

let testString: string

testString = "hello"

let testBoolean: boolean

testBoolean = false

// Multiple Type Assignment
let testStringOrNumber: string | number

testStringOrNumber = "hello"

testStringOrNumber = 55


// ARRAY
let names = ["John", "Jane", "Tom"]

//names.push(55)

names.push("Riccardo")

let testStringsArray: string[]

//testStringsArray = [5,7,8]

testStringsArray = ["Tom", "Dick", "Harry"]

let testStringOrNumberArray: (string | number)[]

testStringOrNumberArray = ["John", 55, "Chicago"]


// Objects
let user = {
  userName: "John",
  age: 55,
  isAdmin: false
}

user.userName = "Jane"
//user.userName = 55

//user.phone = "5555555555"

let userObj : {
  userName: String,
  age: Number,
  isAdmin: Boolean
}

userObj = {
  userName: "john",
  age: 65,
  isAdmin: false,
  //phone: 5555555555
}

// Object with optional
let userObj2 : {
  userName: String,
  age: Number,
  isAdmin: Boolean,
  phone?: string
}

userObj2 = {
  userName: "James",
  age: 45,
  isAdmin: true,
  phone: "5555555555"
}

// Functions
let sayHi = ()=>{
  console.log("Hi, welcome")
}

let funcReturnString = ():string =>{
  console.log("Hello")
  return "dev"
}

let funcTakeArg = (num : number): number =>{
  //console.log(num)
  return num*2
}

let funcTakeArg2 = (num : number) =>{
  //console.log(num)
  return num*2
}

let funcTakeArg3 = (num : number): void =>{
  //console.log(num)
  //return num*2
}

let sum = (num: number, num2:number) => {
  return num+num2
}

console.log(sum(5,6))

let func = (user:{username:string, age:number, phone?:string})=>{
  console.log(user.username)
}

// Make it easier to read by using Type Aliases
type UserType = {
  userName: string,
  age: number,
  phone?: string
}

let betterFunc = (user:UserType)=>{
  console.log(user.userName)
}

type myFunc2 = (a:number, b:string) => void

let write : myFunc2 = (num,str) =>{
  console.log(num + " times " + str)
}

type UserType2 = {
  username: string,
  age: number,
  phone?: string,
  theme: "dark" | "light"
}

const userWithTheme : UserType2 = {
  username:"riccardo",
  age:38,
  //theme: "pink",
  theme:"light"
}

//INTERFACES
interface IUser {
  username: string,
  email: string,
  age: number
}

interface IEmployee extends IUser {
  employeeId: number
}

const emp : IEmployee = {
  username: "John",
  email: "john@john.com",
  age: 56,
  employeeId: 5678
}

const user2 : IUser = {
  username: "John",
  email: "john@john.com",
  age: 56,
  
}


//Generics

