import { create } from "zustand";
import type { Campaign } from "@/types/campaign";

interface CampaignState {
  campaigns: Campaign[];
  activeCampaign: Campaign | null;
  loading: boolean;
  setCampaigns: (campaigns: Campaign[]) => void;
  setActiveCampaign: (campaign: Campaign | null) => void;
  setLoading: (loading: boolean) => void;
}

export const useCampaignStore = create<CampaignState>((set) => ({
  campaigns: [],
  activeCampaign: null,
  loading: false,
  setCampaigns: (campaigns) => set({ campaigns }),
  setActiveCampaign: (campaign) => set({ activeCampaign: campaign }),
  setLoading: (loading) => set({ loading }),
}));
