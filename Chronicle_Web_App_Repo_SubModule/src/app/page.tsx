"use client";
//Artem Branch
import Image from "next/image";
import Link from "next/link";
import RoundedGreenButton from "@/components/rounded-green-button";
import RoundedGreyButton from "@/components/Rounded-Grey-Button";
import { useForm } from "react-hook-form";
import { useRouter } from "next/navigation";
import React, { useState } from "react";
import { authenticateUser } from "@/lib/authenticate";
import { getUser } from "@/lib/userData";
import { UserData } from "@/store/UserSlice";
import { setUser } from "@/store/UserSlice";
import { useDispatch } from "react-redux";
import Cookies from "js-cookie";
import { BsFillEyeSlashFill, BsEyeFill } from 'react-icons/bs';

const IndexPage = () => {
  const router = useRouter();
  const [warning, setWarning] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const dispatch = useDispatch();

  type FormData = {
    user: string;
    password: string;
  };

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<FormData>({
    defaultValues: {
      user: "",
      password: "",
    },
  });

  async function submitForm(data: FormData) {
    const { user, password } = data;

    if (!user || !password) {
      setWarning("All fields are required!");
      return;
    }

    try {
      const id = await authenticateUser(user, password);
      if (id) {
        let userDataRes = await getUser(id);
        console.log("User data: ", userDataRes);
        updateUserSlice(userDataRes);
        //Set Cookie after login
        Cookies.set("loggedIn", "true");
        router.push("/home");
      } else {
        setWarning("Authentication failed");
      }
    } catch (err) {
      if (err instanceof Error) {
        setWarning(err.message);
      } else {
        throw err;
      }
    }
    reset();
  }

  async function updateUserSlice(userDataRes: UserData) {
    const userReduxData = {
      _id: userDataRes._id,
      USER_NAME: userDataRes.USER_NAME,
      PASSWORD: userDataRes.PASSWORD,
      CONFIRM_PASSWORD: userDataRes.CONFIRM_PASSWORD,
      EMAIL_ADDRESS: userDataRes.EMAIL_ADDRESS,
      TERMS: userDataRes.TERMS,
      FIRST_NAME: userDataRes.FIRST_NAME,
      LAST_NAME: userDataRes.LAST_NAME,
      IS_ACTIVE: userDataRes.IS_ACTIVE,
      DATE_CREATED: userDataRes.DATE_CREATED,
      SECURITY_QUESTION: userDataRes.SECURITY_QUESTION,
      SECURITY_ANSWER: userDataRes.SECURITY_ANSWER,
      JOURNAL_ENTRIES: userDataRes.JOURNAL_ENTRIES,
      PROFILE_IMAGE_ID: userDataRes.PROFILE_IMAGE_ID
    };

    console.log("Updated Redux Store:", userReduxData);
    console.log("User Email: ", userReduxData.EMAIL_ADDRESS);
    dispatch(setUser(userReduxData));
  }

  return (
    <>
      <div className="flex flex-col min-h-screen justify-center items-center bg-gradient-to-tl from-green-200 to-white">
        {/* Welcome Banner */}
        <div className="bg-white rounded-md p-4 border border-green-500">
        <section className="flex space-x-4 py-6 justify-center items-center">
          <Image
            src="/banner-chronicle-transparent.png"
            width={240}
            height={45}
            alt="app-logo"
            priority
          />
        </section>

        {/* Sign-In Components */}

        <section className="flex flex-col space-y-4 justify-center items-center">
          <form
            onSubmit={handleSubmit(submitForm)}
            className="flex flex-col space-y-4 py-6 justify-center items-center"
          >
            <div className="mb-2">
              <label
                className="block text-sm font-medium leading-6 text-gray-900"
                htmlFor="user"
              >
                Username
              </label>
              <input
                {...register("user", { required: true })}
                id="user"
                className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                type="text"
                placeholder="Username"
              />
              {errors.user && (
                <span className="text-red-500 text-xs italic">
                  Please enter a username.
                </span>
              )}
            </div>
            <div className="mb-4">
              <label
                className="block text-sm font-medium leading-6 text-gray-900"
                htmlFor="password"
              >
                Password
              </label>
              <div className="relative">
              <input
                {...register("password", { required: true })}
                id="password"
                className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                type={showPassword ? "text" : "password"}
                placeholder="Password"
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 px-3 py-2"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
              </button>
              </div>
              {errors.password && (
                <p className="text-red-500 text-xs italic">
                  Please enter a password.
                </p>
              )}
            </div>

            {/* Forgot Password */}
            <div className="mb-4">
              <Link href="/forgotPassword" legacyBehavior>
                <a className="text-blue-500 hover:underline" style={{ fontSize: '13px' }}>Forgot Password?</a>
              </Link>
            </div>

            <br />

            <div className="flex flex-col w-[200px]">
              <RoundedGreenButton text="Sign In" type="submit" />
            </div>

            {warning && (
              <span className="bg-red-500 text-white w-fit px-1 text-sm rounded-md mt-2">
                {warning}
              </span>
            )}
          </form>
        </section>

        {/* Register Text */}

        <section className="text-green-900 font-semibold text-center text-md pt-5">
          <h3 className="pb-2">Need an Account?</h3>
          <h3>Click Register to Begin Your Chronicle</h3>
        </section>

        {/* Register Button */}
          <div className="flex space-x-4 py-6 justify-center">
            <RoundedGreyButton text="Register" link="/register"/>
            </div>
        </div>
      </div>
    </>
  );
};

export default IndexPage;
