//src/app/forgotPassword.tsx
"use client";

import React, { useState } from "react";    
import Link from "next/link";
import RoundedGreenButton from "@/components/rounded-green-button";
import RoundedGreyButton from "@/components/Rounded-Grey-Button";
import { useForm } from "react-hook-form";
import { useRouter } from "next/navigation";
import Image from "next/image";
import { useDispatch, useSelector } from "react-redux";
import Cookies from "js-cookie";
import { authenticateFPUser, retrieveUser } from "@/lib/authenticate";
import { getUser } from "@/lib/userData";
import { setUser, userSlice } from "@/store/UserSlice";
import UnAuthUserSlice, { setUnAuthUser } from "@/store/UnAuthUserSlice";  
import { unAuthUserData } from "@/store/UnAuthUserSlice";
import { UserData } from "@/store/UserSlice";
import { RootState } from "@/store/store";
import { BsFillEyeSlashFill, BsEyeFill } from 'react-icons/bs';

const ForgotPasswordPage = () => {

    const uaUser = useSelector((state: RootState) => state.uaUser);

    const [warning, setWarning] = useState("");
    const [answerWarning, setAnswerWarning] = useState("");
    const [showAns, setShowAns] = useState(false);
    const router = useRouter();
    const dispatch = useDispatch();

    type fpData = {
        user: string;
        email: string;
        securityAnswer: string;
    };

    const [isAuthenticated, setIsAuthenticated] = useState(false);

    const {
        register,
        handleSubmit,
        formState: { errors },
        reset,
      } = useForm<fpData>({
        defaultValues: {
          user: "",
          email: "",
          securityAnswer: "",
        },
    });
    
    async function submitForm(data: fpData) {

        // if the user is already authenticated and on a retrieve account pages, then clicking on the retrieve account button will call the if block below
        if (isAuthenticated) {
            console.log("User is already authenticated and on a retrieve account page");
            const { securityAnswer } = data;
            let user = uaUser.USER_NAME;
            console.log("Security Answer: ", securityAnswer);
            console.log("Retrieve User : ", user);

            if (!securityAnswer) {
                setAnswerWarning("Security Answer is required!");
                return;
            }

            try {   
                console.log("calling retrieveUser for user: ", user, " and securityAnswer: ", securityAnswer);
                const id = await retrieveUser(user, securityAnswer);
                console.log("user id: ", id);
                if (id) {
                    let userDataRes = await getUser(id);
                    console.log("User data: ", userDataRes);
                    console.log("User AUTHENTICATED password: ", userDataRes.USER_PASS);
                    console.log("User AUTHENTICATED confirm password: ", userDataRes.USER_PASS2);
                    if (isAuthenticated) {
                        updateUserSlice(userDataRes);
                    }
                    else{
                        updateFPUserSlice(userDataRes);
                    }
                    //Set Cookie after login
                    Cookies.set("loggedIn", "true");
                    router.push("/forgotPassword/createPassword");
                } else {
                    setAnswerWarning("Authentication failed");
                }
            } catch (err) {  
                if (err instanceof Error) {
                    setAnswerWarning(err.message);
                } else {
                    throw err;
                }
            }
            reset();
        }
        else {
            const { user, email } = data;
        
            if (!user || !email) {
                setWarning("All fields are required!");
                return;
            }

            try {
                console.log("user id: ", user);
                console.log("user email: ", email);
                console.log("calling authenticateFPUser ");
                const id = await authenticateFPUser(user, email);
                console.log("user id: ", id);
                if (id) {
                    let userDataRes = await getUser(id);
                    console.log("User data: ", userDataRes);
                    updateFPUserSlice(userDataRes);
                    setIsAuthenticated(true);
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
    }

    //if the user us authenticated, then update the user slice
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
        };
    
        console.log("Updated Retrieve Redux Store:", userReduxData);
        console.log("User Email: ", userReduxData.EMAIL_ADDRESS);
        console.log("User Password: ", userReduxData.PASSWORD);
        console.log("User ConfirmPassword: ", userReduxData.CONFIRM_PASSWORD);
        dispatch(setUser(userReduxData));
    }
    
    //when the user is unAuthenticated, update the unAuthUserData slice
    async function updateFPUserSlice(userDataRes: unAuthUserData) {
        console.log("User data res: ", userDataRes);
        const userReduxData = {
          _id: userDataRes._id,
          USER_NAME: userDataRes.USER_NAME,
          EMAIL_ADDRESS: userDataRes.EMAIL_ADDRESS,
          SECURITY_QUESTION: userDataRes.SECURITY_QUESTION,
          SECURITY_ANSWER: userDataRes.SECURITY_ANSWER,
        };
    
        console.log("Updated unAuth Redux Store:", userReduxData);
        console.log("User Email: ", userReduxData.EMAIL_ADDRESS);
        dispatch(setUnAuthUser(userReduxData));
    }

    return (
        <>
            <div className="flex flex-col min-h-screen justify-center items-center bg-gradient-to-tl from-green-200 to-white">

                <div className="bg-white rounded-md p-4 border border-green-500">

                    {/* Welcome Banner */}
                    <section className="flex space-x-4 py-6 justify-center items-center">
                    <Image
                        src="/banner-chronicle-transparent.png"
                        width={240}
                        height={45}
                        alt="app-logo"
                        priority
                    />
                    </section>
                        
                    {/* Forgot Password Form */}

                    <section className="flex flex-col space-y-4 py-1 justify-center items-center">
                        <form 
                            onSubmit={handleSubmit(submitForm)}
                            className="flex flex-col space-y-4 py-6 justify-center items-center">

                            <div className="mb-2" style={{ fontSize: '27px', fontFamily:'sans-serif'}}>
                                Forgot Password?        
                            </div>
                            
                            { !isAuthenticated && (
                                <>
                                    {/**asking user to enter username and email */}
                                    <div className="mb-2">
                                        <label className="block text-md font-medium leading-6 text-gray-900" htmlFor="user">Username</label>
                                        <input
                                            {...register("user", { required: true })}
                                            id="user"
                                            className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                            type="text"
                                            placeholder="Username"
                                        />
                                        {errors.user && (
                                            <span className="text-red-500 text-xs italic font-bold">
                                            Please enter a username.
                                            </span>
                                        )}
                                    </div>

                                    <div className="mb-2">
                                        <label className="block text-md font-medium leading-6 text-gray-900" htmlFor="email">Email</label>
                                        <input
                                            {...register("email", { required: true })}
                                            id="email"
                                            className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                            type="email"
                                            placeholder="Email"
                                        />
                                        {errors.email && (
                                            <span className="text-red-500 text-xs italic">
                                            Please enter an email.
                                            </span>
                                        )}
                                    </div>
                                    <br />

                                    {warning && (
                                        <span className="bg-red-500 text-white w-fit px-1 text-sm rounded-md mt-2">
                                            {warning}
                                        </span>
                                    )}

                                    <div className="flex flex-col w-[200px]">
                                        <RoundedGreenButton text="Authenticate MySelf" type="submit" />
                                    </div>

                                    <Link href="/home">
                                        <div className="flex flex-col w-[200px]">
                                            <RoundedGreyButton text="Cancel" type="button"/>
                                        </div>
                                    </Link>
                                </>
                            )}


                            { isAuthenticated && (
                                <>
                                    <div className="mb-2">
                                    <label className="block text-md font-medium leading-6 text-gray-1100" htmlFor="security-question">Answer the Below Security Question.</label>
                                    <br />
                                    <label className="block text-md font-medium leading-6 text-gray-900" htmlFor="security-question">{uaUser.SECURITY_QUESTION}</label>
                                    <div className="relative">
                                        <input
                                            {...register("securityAnswer", { required: true })}
                                            id="security-answer"
                                            className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                            type={showAns ? "text" : "password"}
                                            placeholder="Security Answer"
                                        />
                                        <button
                                            type="button"
                                            className="absolute inset-y-0 right-0 px-3 py-2"
                                            onClick={() => setShowAns(!showAns)}
                                        >
                                            {showAns ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                                        </button>
                                    </div>
                                    {errors.securityAnswer && (
                                        <span className="text-red-500 text-xs italic">
                                        Please enter the Security Answer.
                                        </span>
                                    )}
                                    </div>

                                    <br />

                                    {answerWarning && (
                                        <span className="bg-red-500 text-white w-fit px-1 text-sm rounded-md mt-2">
                                            {answerWarning}
                                        </span>
                                    )}

                                    <div className="flex flex-col w-[200px]">
                                        <RoundedGreenButton text="Retrieve Account" type="submit" />
                                    </div> 

                                    <Link href="/home">
                                        <div className="flex flex-col w-[200px]">
                                            <RoundedGreyButton text="Cancel" type="button"/>
                                        </div>
                                    </Link>
                                </>
                            )}

                        </form>
                    </section>
            
                </div>
            </div>
        </>
    );
}

export default ForgotPasswordPage;