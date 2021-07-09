package com.um.inf.olchain.services;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.bumptech.glide.Glide;
import com.bumptech.glide.load.engine.DiskCacheStrategy;
import com.um.inf.olchain.R;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class ServicesAdapter extends RecyclerView.Adapter<ServicesAdapter.ViewHolder> {
    private List<ServiceListModel> serviceModelList;
    private OnServiceListener onServiceListener;

    public ServicesAdapter(List<ServiceListModel> serviceModelList, OnServiceListener onServiceListener) {
        this.serviceModelList = serviceModelList;
        this.onServiceListener = onServiceListener;
    }

    @NonNull
    @Override
    public ServicesAdapter.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.service_list_row, parent, false);
        ViewHolder viewHolder = new ViewHolder(v, onServiceListener);
        return viewHolder;
    }

    @Override
    public void onBindViewHolder(@NonNull ServicesAdapter.ViewHolder holder, int position) {
        String name = serviceModelList.get(position).getName();
        URL imgUrl = null;
        try {
            imgUrl = new URL(serviceModelList.get(position).getImage());
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        if (serviceModelList.get(position).isledgerPolicyCoincidence()) {
            holder.imgLock.setVisibility(View.VISIBLE);
            holder.imgWarning.setVisibility(View.GONE);
        } else {
            holder.imgWarning.setVisibility(View.VISIBLE);
            holder.imgLock.setVisibility(View.GONE);
        }
        holder.serviceName.setText(name);
        Glide.with(holder.imgService.getContext()).load(imgUrl).diskCacheStrategy(DiskCacheStrategy.ALL).into(holder.imgService);
    }

    @Override
    public int getItemCount() {
        return serviceModelList.size();
    }

    public static class ViewHolder extends RecyclerView.ViewHolder implements View.OnClickListener{
        private TextView serviceName;
        private ImageView imgService;
        private ImageView imgLock;
        private ImageView imgWarning;
        OnServiceListener onServiceListener;

        public ViewHolder(@NonNull View itemView, OnServiceListener onServiceListener) {
            super(itemView);
            serviceName = itemView.findViewById(R.id.servicesListText);
            imgService = itemView.findViewById(R.id.imgService);
            imgLock = itemView.findViewById(R.id.lockImage);
            imgWarning = itemView.findViewById(R.id.imageWarning);
            this.onServiceListener = onServiceListener;
            itemView.setOnClickListener(this);
        }

        @Override
        public void onClick(View v) {
            onServiceListener.onClick(getAdapterPosition());
        }
    }

    public interface OnServiceListener {
        void onClick(int index);
    }
}
