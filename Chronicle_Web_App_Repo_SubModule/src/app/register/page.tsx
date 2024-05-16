"use client";

import React, { useState } from "react";
import Image from "next/image";
import Link from "next/link";
import RoundedGreenButton from "../../components/rounded-green-button";
import RoundedGreyButton from "@/components/Rounded-Grey-Button";
import { useForm } from "react-hook-form";
import { useRouter } from "next/navigation";
import { registerUser } from "@/lib/authenticate";
import { BsFillEyeSlashFill, BsEyeFill } from 'react-icons/bs';

const Register = () => {
  const router = useRouter();
  const [warning, setWarning] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfPassword, setConfShowPassword] = useState(false);
  const [showAns, setShowAns] = useState(false);

  type FormData = {
    user: string;
    password: string;
    confirmPassword: string;
    email: string;
    terms: boolean;
    firstName: string;
    lastName: string;
    securityQuestion: string;
    securityAnswer: string;
  };

  const { register, handleSubmit } = useForm({
    defaultValues: {
      user: "",
      password: "",
      confirmPassword: "",
      email: "",
      terms: false,
      firstName: "",
      lastName: "",
      securityQuestion: "",
      securityAnswer: "",
    },
  });

  async function submitForm(data: FormData) {
    //e.preventDefault();
    console.log("data type is: ", data);
    //console.log(typeof data)
    // All fields are required

    // Destructure values from data
    const {
      user,
      password,
      confirmPassword,
      email,
      firstName,
      lastName,
      terms,
      securityQuestion,
      securityAnswer,
    } = data;


    // All fields are required
    if (
      !user ||
      !password ||
      !confirmPassword ||
      !email ||
      !firstName ||
      !lastName ||
      
      !securityQuestion ||
      !securityAnswer
    ) {
      setWarning("All fields are required");
      setTimeout(() => {
        setWarning("");
      }, 5000);

      return;
    }

    // Password and confirmPassword must match
    if (password !== confirmPassword) {
      setWarning("Passwords do not match");
      setTimeout(() => {
        setWarning("");
      }, 5000);
      return;
    }

    // Email must be in the correct format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setWarning("Invalid email format");
      setTimeout(() => {
        setWarning("");
      }, 5000);
      return;
    }

    // Password length must be between 8 and 16 characters
    if (password.length < 8 || password.length > 16) {
      setWarning("Password must be between 8 and 16 characters");
      setTimeout(() => {
        setWarning("");
      }, 5000);
      return;
    }

    // Password must contain at least one special character
    const specialCharacterRegex = /[!@#$%^&*?]/;
    if (!specialCharacterRegex.test(password)) {
      setWarning(
        "Password must contain at least one special character (!@#$%^&*?)"
      );
      setTimeout(() => {
        setWarning("");
      }, 5000);
      return;
    }

    // Checkbox must be checked
    if (!terms) {
      setWarning("You must accept the terms and conditions");
      setTimeout(() => {
        setWarning("");
      }, 5000);
      return;
    }

    try {
      console.log("registering user");
      await registerUser(
        firstName,
        lastName,
        user,
        password,
        confirmPassword,
        email,
        terms,
        securityQuestion,
        securityAnswer
      );
      console.log("user registered");
      router.push("/");
    } catch (err) {
      if (err instanceof Error) {
        setWarning(err.message);
        console.log("error");
      } else {
        // Handle other types of errors or rethrow them
        throw err;
      }
    }
  }

  const securityQuestions = [
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What is the name of your first pet?",
    "What is the model of your first car?",
    "What is your favorite movie?",
    "What is the name of your favorite teacher?",
    "What is your favorite book?",
    "What is the name of the street you grew up on?",
    "What is your favorite food?",
    "What is the name of your childhood best friend?"
  ];

  return (
    <>
      <div className="flex flex-col min-h-screen justify-center items-center bg-gradient-to-tl from-green-100 to-white">
        <div className="bg-white rounded-md p-4 m-4 border border-green-500  bg-gradient-to-t from-white to-emerald-100">
          {/* Welcome Banner */}
          <section className="flex space-x-4 justify-center items-center">
            <Image
              src="/banner-chronicle-transparent.png"
              width={240}
              height={45}
              alt="app-logo"
              priority
            />
          </section>

          {/* Welcome Text */}
          <section className="text-green-900 text-lg font-bold text-center pt-5">
            <h1>Sign up to Begin Your</h1>
            <h1>Chronicle Experience</h1>
            {/* <h1 className="mt-1 text-xs">(All Fields Are Required)</h1> */}

            <label className="mt-1 text-xs text-gray-500">
              Please Fill Out the Form Below to Create an Account
              <br/> 
              All Fields Are Required
            </label>
          </section>

          {/* Form */}
          <section className="flex flex-col space-y-4 justify-center items-center">
            <form
              onSubmit={handleSubmit(submitForm)}
              className="flex flex-col space-y-4 py-6 justify-center items-center"
            >
              <input
                {...register("firstName")}
                className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                placeholder="First Name"
              />
              <input
                {...register("lastName")}
                className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                placeholder="Last Name"
              />
              <input
                {...register("email")}
                className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                placeholder="Email"
              />
              <input
                {...register("user")}
                className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                placeholder="Username"
              />
              <div className="relative w-full">
                <input
                  {...register("password")}
                  className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  placeholder="Password"
                  type={showPassword ? "text" : "password"}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 px-3 py-2"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                </button>
              </div>
              <div className="relative w-full">
                <input
                  {...register("confirmPassword")}
                  className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  placeholder="Confirm Password"
                  type={showConfPassword ? "text" : "password"}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 px-3 py-2"
                  onClick={() => setConfShowPassword(!showConfPassword)}
                >
                  {showConfPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                </button>
              </div>
              {/* Security Question */}
              <div>
                <label
                  className="block text-md font-medium leading-6 text-gray-900"
                  htmlFor="securityQuestion"
                >
                  Select a Security Question:
                </label>
              </div>


              <select {...register("securityQuestion")} className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6">
                {securityQuestions.map((question, index) => (
                  <option key={index} value={question}>
                    {question}
                  </option>
                ))}
              </select>

              {/* Security Answer */}
              <div className="relative w-full">
                <input
                  {...register("securityAnswer")}
                  className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  placeholder="Enter Your Answer Here"
                  type={showAns ? "text" : "password"}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 px-3 py-2"
                  onClick={() => setShowAns(!showAns)}
                >
                  {showAns ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                </button>
              </div>
              

              <div className="flex items-center pt-4">
                <input
                  {...register("terms")}
                  type="checkbox"
                  className="text-green-500 font-semibold outline-black border border-black rounded outline-1 pl-2"
                />
                <label className="ml-2" htmlFor="terms">
                  <span>I agree to the </span>
                  <span>
                    <Link href="/terms" className="text-green-500  hover:text-green-700">
                      Terms and Conditions
                    </Link>
                  </span>
                </label>
              </div>

              {/* Warning */}

              {warning && (
                <span className="bg-red-500 text-white w-fit px-1 text-sm rounded-md mt-2">
                  {warning}
                </span>
              )}

              {/* Register Button */}
              <div className="flex flex-col space-y-4 py-4 justify-center items-center">
                <RoundedGreyButton type="submit" text="Register" />
              </div>
            </form>
          </section>

          {/* Existing Account Text */}
          <div className="flex justify-center">
            <label className="ml-2" htmlFor="terms">
              <span>Already Have an Account? </span>
              <span>
                <Link href="/" className="text-green-500 hover:text-green-700">
                  Log In
                </Link>
              </span>
            </label>
          </div>
        </div>
      </div>
    </>
  );
};

export default Register;
