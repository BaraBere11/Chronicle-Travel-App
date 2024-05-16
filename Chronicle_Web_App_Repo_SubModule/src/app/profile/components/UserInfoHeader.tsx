"use client";
import React from "react";
import { RootState } from "@/store/store";
import { useSelector } from "react-redux";

const UserInfoHeader = () => {
  const user = useSelector((state: RootState) => state.user);
  console.log("Profile Page Log: ", user);

  return (
    <div className="flex items-center justify-center h-full">
      <div className="flex flex-col items-center">
        <div className="pl-2 text-2xl font-semibold mb-1 flex flex-col items-center">{`${user.FIRST_NAME} ${user.LAST_NAME}`}
        </div>
        <div className="pl-2 text-gray-600 font-semibold">@{user.USER_NAME}</div>
        <div className="mt-4 flex flex-col">
          <div className="text-lg flex flex-col items-center">
          <p className="text-lg text-black font-semibold mt-4">Email</p>
          <p className="text-sm text-gray-900">{user.EMAIL_ADDRESS}</p>
            <div className="text-lg text-black font-semibold flex flex-col items-center mt-4">Chronicle Member Since</div>
            <div className="text-sm flex flex-col items-center">{` ${
              typeof user.DATE_CREATED === "string"
                ? user.DATE_CREATED.substring(0, 9)
                : user.DATE_CREATED
            }`}</div>
            
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserInfoHeader;
