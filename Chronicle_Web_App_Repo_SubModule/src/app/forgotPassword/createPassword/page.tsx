'use client';

import React, { useState, ChangeEvent, FormEvent } from 'react';
import Link from 'next/link'; 
import { useForm } from 'react-hook-form';
import RoundedGreenButton from '@/components/rounded-green-button';
import RoundedGreyButton from '@/components/Rounded-Grey-Button';
import { useRouter } from 'next/navigation';
import { useSelector } from 'react-redux';
import { RootState } from '@/store/store';
import { useDispatch } from 'react-redux'
import Image from 'next/image';
import { createUserPassword } from "@/lib/userData";
import { setUser } from "@/store/UserSlice";
import { BsFillEyeSlashFill, BsEyeFill } from 'react-icons/bs';

const CreatePassword = () => {

  const dispatch = useDispatch();
  const router = useRouter();
  const user = useSelector((state: RootState) => state.user);

  const [warning, setWarning] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfPassword, setConfShowPassword] = useState(false);

  type cpData = {
    newPassword: string;
    confirmNewPassword: string;
  };  

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<cpData>({
    defaultValues: {
      newPassword: "",
      confirmNewPassword: "",
    },
  });

  async function submitForm(data: cpData) {

    console.log("inside submit Form: ", data.newPassword, data.confirmNewPassword);
    console.log("user name: ", user.USER_NAME);    
    console.log("user: ", user);
  
    const updatedPasswordData = {
        ...user,
        PASSWORD: data.newPassword,
        CONFIRM_PASSWORD: data.confirmNewPassword,
    };

    
    if(data.newPassword !== data.confirmNewPassword) {
        setWarning("New Password and Confirm New Password do not match");
        return;
    }

    // new Password length must be between 8 and 16 characters
    if (data.newPassword.length < 8 || data.newPassword.length > 16) {
        setWarning("New Password must be between 8 and 16 characters");
        return;
    }

    // new Password must contain at least one special character
    const specialCharacterRegex = /[!@#$%^&*?]/;
    if (!specialCharacterRegex.test(data.newPassword)) {
        setWarning(
          "New Password must contain at least one special character (!@#$%^&*?)"
        );
    return;
    }

      try {
        console.log("calling create Password function from inside submitForm:");
        let id = user._id;
        if(id){
            console.log("User ID: ", id);
            console.log("Before CALLING API - Updated Password Data: ", updatedPasswordData);
          let userDataRes = await createUserPassword(id, updatedPasswordData);
          console.log("User data: ", userDataRes);
          
          updateUserSlice();

          setSuccessMessage('New Password created successfully! Logging in... Please wait!');
          setTimeout(() => {
            setTimeout(() => {
              router.push('/home');
            }, 2000);
          }, 2000);
        }
        else {
          setWarning('Authentication failed');
        }
      }
      catch (err) {
        if (err instanceof Error) {
          setWarning(err.message);
        } else {
          throw err;
        }
      }

    async function updateUserSlice() {
      const userReduxData = {
        _id: user._id,
        USER_NAME: user.USER_NAME,
        PASSWORD: data.newPassword, 
        CONFIRM_PASSWORD: data.confirmNewPassword, 
        EMAIL_ADDRESS: user.EMAIL_ADDRESS,
        TERMS: user.TERMS,
        FIRST_NAME: user.FIRST_NAME,
        LAST_NAME: user.LAST_NAME,
        IS_ACTIVE: user.IS_ACTIVE,
        DATE_CREATED: user.DATE_CREATED,
        PROFILE_IMAGE_ID: user.PROFILE_IMAGE_ID
      };
    
      console.log("Password Updated Redux Store:", userReduxData);
      console.log("User Email: " , userReduxData.EMAIL_ADDRESS);
      dispatch(setUser(userReduxData));
      
    }  
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
            <div className="flex justify-center items-center">
            <div className="bg-white p-10 rounded-md">
            <div className="mb-2 flex justify-center items-center">
                <h2 className="text-2xl font-bold ">Create <span className="text-green-500 ">New Password</span></h2>
            </div>
            <div className="mb-10 flex justify-center items-center">
                <h2 className="text-2xl font-bold">And <span className="text-green-500">Log In</span></h2>
            </div>
                
                <form onSubmit={handleSubmit(submitForm)} className="space-y-8">

                    <div>
                    <label htmlFor="newPassword" className="block text-md font-medium text-black-900 font-sans">
                        New Password:
                    </label>
                    <div className="relative">
                      <input
                          {...register("newPassword", {required: true})}
                          type={showPassword ? "text" : "password"}
                          id="newPassword"
                          name="newPassword"
                          className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                      />
                      <button
                        type="button"
                        className="absolute inset-y-0 right-0 px-3 py-2"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                      </button>
                    </div>
                    {errors.newPassword && (
                        <span className="text-red-500 text-xs italic font-bold">
                        Please enter the New Password.
                        </span>
                    )}
                    </div>  

                    <div>
                    <label htmlFor="confirmNewPassword" className="block text-md font-medium text-black-900 font-sans">
                        Confirm New Password:
                    </label>
                    <div className="relative">
                      <input
                        {...register("confirmNewPassword", {required: true})}
                        type={showConfPassword ? "text" : "password"}
                        id="confirmNewPassword"
                        name="confirmNewPassword"
                        className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                      />
                      <button
                        type="button"
                        className="absolute inset-y-0 right-0 px-3 py-2"
                        onClick={() => setConfShowPassword(!showConfPassword)}
                      >
                        {showConfPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                      </button>
                    </div>
                    {errors.confirmNewPassword && (
                        <span className="text-red-500 text-xs italic font-bold">
                        Please re-enter the New Password.
                        </span>
                    )}
                </div>

                <br />

            
                {/* Warning */}

                {warning && !successMessage && (
                    <span className="bg-red-500 text-white w-fit px-1 text-sm rounded-md mt-2">
                    {warning}
                    </span>
                )}

                {successMessage && (
                  <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex justify-center items-center">
                    <div className="bg-green-500 text-white ml-2 mr-2 px-2 py-2 text-md rounded-md justify-center text-center">
                      {successMessage}
                    </div>
                  </div>
                )}

                <div className="flex flex-col items-center justify-center">
                    <div className="flex flex-col w-[250px]">
                    <RoundedGreenButton text="Create Password and Log In" type="submit" />
                    </div>
                </div>

                <div className="flex flex-col items-center justify-center">
                    <Link href="/forgotPassword">
                    <div className="flex flex-col w-[250px]">
                    <RoundedGreyButton text="Go Back" type="button" />
                    </div>
                    </Link>
                </div>

                </form>
            </div>
            </div>
        </div>
    </div>
    </>
  )
}

export default CreatePassword;